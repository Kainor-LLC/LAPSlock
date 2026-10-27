#!/usr/bin/env python3
"""Checks every call in manifest.json against Microsoft Graph's published schema.

For each call it walks the path through the $metadata document: the entity set or
singleton, each key, each navigation property, and the bound action or function at the
end. Then it checks that every field the app selects or expands, and every action
parameter it sends, still exists on that type. No sign-in: $metadata is public.

    python3 check_schema.py manifest.json [--metadata-dir DIR] [--json OUT]

Exit 0 when everything resolves, 1 when something is missing, 2 when the schema could
not be read. --metadata-dir reads v1.0.xml and beta.xml from disk instead of fetching.
"""
import json
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

EDM = "{http://docs.oasis-open.org/odata/ns/edm}"


class Schema:
    def __init__(self, xml_bytes):
        root = ET.fromstring(xml_bytes)
        self.aliases = {}
        self.types = {}        # full name -> element (EntityType or ComplexType)
        self.bound = {}        # bound type full name (or Collection(x)) -> {name: element}
        self.sets = {}         # entity set / singleton name -> type full name (Collection(...) for sets)
        schemas = list(root.iter(EDM + "Schema"))
        for s in schemas:
            if s.get("Alias"):
                self.aliases[s.get("Alias")] = s.get("Namespace")
        for s in schemas:
            ns = s.get("Namespace")
            for kind in ("EntityType", "ComplexType"):
                for t in s.findall(EDM + kind):
                    self.types[ns + "." + t.get("Name")] = t
            for kind in ("Action", "Function"):
                for op in s.findall(EDM + kind):
                    if op.get("IsBound") != "true":
                        continue
                    params = op.findall(EDM + "Parameter")
                    if not params:
                        continue
                    bound_to = self.full(params[0].get("Type"))
                    self.bound.setdefault(bound_to, {})[op.get("Name")] = op
            for container in s.findall(EDM + "EntityContainer"):
                for es in container.findall(EDM + "EntitySet"):
                    self.sets[es.get("Name")] = "Collection(" + self.full(es.get("EntityType")) + ")"
                for sg in container.findall(EDM + "Singleton"):
                    self.sets[sg.get("Name")] = self.full(sg.get("Type"))

    def full(self, name):
        if name is None:
            return None
        if name.startswith("Collection(") and name.endswith(")"):
            return "Collection(" + self.full(name[11:-1]) + ")"
        for alias, ns in self.aliases.items():
            if name.startswith(alias + "."):
                return ns + name[len(alias):]
        return name

    def lineage(self, type_name):
        """The type and its base types, nearest first."""
        seen = []
        current = type_name
        while current and current in self.types and current not in seen:
            seen.append(current)
            current = self.full(self.types[current].get("BaseType"))
        return seen

    def derived(self, type_name):
        """Types that derive from type_name, so a property on a subtype still counts."""
        out = []
        for name in self.types:
            if type_name in self.lineage(name)[1:]:
                out.append(name)
        return out

    def member(self, type_name, name):
        """A structural or navigation property on the type or its bases: (kind, type)."""
        for t in self.lineage(type_name):
            el = self.types[t]
            for kind in ("Property", "NavigationProperty"):
                for p in el.findall(EDM + kind):
                    if p.get("Name") == name:
                        return kind, self.full(p.get("Type"))
        return None

    def operation(self, type_name, is_collection, name):
        candidates = []
        for t in self.lineage(type_name):
            candidates.append("Collection(" + t + ")" if is_collection else t)
        for c in candidates:
            if name in self.bound.get(c, {}):
                return self.bound[c][name]
        return None


def strip_collection(t):
    if t and t.startswith("Collection(") and t.endswith(")"):
        return t[11:-1], True
    return t, False


def resolve(schema, path):
    """Walks the path. Returns (type, is_collection, operation or None, problems)."""
    segments = [s for s in path.split("/") if s]
    first = segments[0]
    if first == "me":
        current, coll = "microsoft.graph.user", False
    elif first in schema.sets:
        current, coll = strip_collection(schema.sets[first])
    else:
        return None, False, None, ["no entity set or singleton named " + first]
    walked = "/" + first
    op = None
    for seg in segments[1:]:
        walked += "/" + seg
        name = seg.split("(")[0]
        if seg.startswith("{"):
            if not coll:
                return current, coll, None, [walked + ": a key on something that is not a collection"]
            coll = False
            continue
        if seg in ("$ref", "$count", "$value"):
            # OData system segments: a reference, a count, a raw value. Nothing to resolve.
            continue
        if op is not None:
            return current, coll, op, [walked + ": path continues after the operation " + op.get("Name")]
        if "." in name:
            # A type cast, such as /memberOf/microsoft.graph.group.
            cast = schema.full(name)
            if cast not in schema.types:
                return current, coll, None, [walked + ": no type named " + name]
            current = cast
            continue
        found = schema.member(current, name)
        if found and found[0] == "NavigationProperty":
            current, coll = strip_collection(found[1])
            continue
        operation = schema.operation(current, coll, name)
        if operation is not None:
            op = operation
            ret = operation.find(EDM + "ReturnType")
            if ret is not None:
                rt, rc = strip_collection(schema.full(ret.get("Type")))
                if rt in schema.types:
                    current, coll = rt, rc
            continue
        # A navigation property that only a derived type has, such as an authentication method subtype.
        hit = None
        for d in schema.derived(current):
            f = schema.member(d, name)
            if f and f[0] == "NavigationProperty":
                hit = f
                break
        if hit:
            current, coll = strip_collection(hit[1])
            continue
        return current, coll, None, [walked + ": " + current + " has no navigation property, action or function named " + name]
    return current, coll, op, []


def check_call(schema, call):
    current, coll, op, problems = resolve(schema, call["path"])
    if problems:
        return problems
    for field in call.get("select", []) + call.get("expand", []):
        found = schema.member(current, field)
        if not found:
            for d in schema.derived(current):
                found = schema.member(d, field)
                if found:
                    break
        if not found:
            problems.append(call["path"] + ": " + current + " has no property " + field)
    if call.get("parameters"):
        if op is None:
            problems.append(call["path"] + ": parameters listed but the path ends on no action")
        else:
            names = {p.get("Name") for p in op.findall(EDM + "Parameter")}
            for p in call["parameters"]:
                if p not in names:
                    problems.append(call["path"] + ": action " + op.get("Name") + " has no parameter " + p)
    method = call["method"]
    if op is not None:
        is_function = op.tag == EDM + "Function"
        if method == "GET" and not is_function:
            problems.append(call["path"] + ": " + op.get("Name") + " is now an action, which takes POST, not GET")
        if method == "POST" and is_function:
            problems.append(call["path"] + ": " + op.get("Name") + " is now a function, which takes GET, not POST")
    return problems


def load(version, metadata_dir):
    if metadata_dir:
        return (Path(metadata_dir) / (version + ".xml")).read_bytes()
    url = "https://graph.microsoft.com/" + version + "/$metadata"
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    manifest = json.loads(Path(argv[1]).read_text())
    metadata_dir = argv[argv.index("--metadata-dir") + 1] if "--metadata-dir" in argv else None
    out = argv[argv.index("--json") + 1] if "--json" in argv else None
    schemas = {}
    try:
        for version in ("v1.0", "beta"):
            schemas[version] = Schema(load(version, metadata_dir))
    except Exception as error:
        print("Could not read the Graph schema: " + str(error))
        return 2
    findings = []
    for call in manifest["calls"]:
        for problem in check_call(schemas[call["version"]], call):
            findings.append({"id": call["id"], "kit": call["kit"], "version": call["version"], "problem": problem})
        # A beta call that has reached v1.0 is worth knowing about, not a break.
        if call["version"] == "beta" and not check_call(schemas["v1.0"], call):
            findings.append({"id": call["id"], "kit": call["kit"], "version": "v1.0", "problem": "now resolves on v1.0 too; consider moving off beta", "info": True})
    breaks = [f for f in findings if not f.get("info")]
    for f in findings:
        print(("INFO  " if f.get("info") else "BREAK ") + f["id"] + " (" + f["kit"] + ", " + f["version"] + "): " + f["problem"])
    print(str(len(manifest["calls"])) + " calls checked, " + str(len(breaks)) + " broken")
    if out:
        Path(out).write_text(json.dumps(findings, indent=2))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

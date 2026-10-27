# Summarises an Instruments Time Profiler export: main-thread time by function, app code first.
# xcrun xctrace export --input run.trace --xpath '/trace-toc/run[@number="1"]/data/table[@schema="time-profile"]' > tp.xml
# python3 -I scripts/perf/tp_summary.py tp.xml
import sys, collections
import xml.etree.ElementTree as ET

def load(path):
    root = ET.parse(path).getroot()
    ids = {}
    for el in root.iter():
        i = el.get("id")
        if i is not None:
            ids[i] = el
    def res(el):
        r = el.get("ref")
        return ids.get(r, el) if r is not None else el
    return root, res

def frames(bt, res):
    out = []
    for f in bt.iter("frame"):
        f = res(f)
        name = f.get("name") or "?"
        b = f.find("binary")
        binary = res(b).get("name") if b is not None else "?"
        out.append((name, binary))
    return out

path = sys.argv[1]
root, res = load(path)
by_thread = collections.Counter()
rows = []
for row in root.iter("row"):
    th = row.find("thread"); w = row.find("weight"); st = row.find("tagged-backtrace")
    if th is None or w is None:
        continue
    th = res(th); w = res(w)
    weight = int(w.text or 0) / 1e6
    tname = th.get("fmt", "?")
    by_thread[tname] += weight
    bt = res(st) if st is not None else None
    rows.append((tname, weight, frames(bt, res) if bt is not None else []))

print("total sampled ms by thread (top 5):")
for t, ms in by_thread.most_common(5):
    print("  %8.0f  %s" % (ms, t))
main = by_thread.most_common(1)[0][0]
total = by_thread[main]
selfw = collections.Counter(); incl = collections.Counter(); appincl = collections.Counter()
for t, w, fr in rows:
    if t != main or not fr:
        continue
    selfw[fr[0][0]] += w
    seen = set()
    for name, binary in fr:
        if name in seen:
            continue
        seen.add(name)
        incl[name] += w
        if "lapslock" in binary.lower():
            appincl[name] += w
print("\nmain thread: %s, %.0f ms sampled" % (main, total))
print("\napp code, inclusive ms (top 15):")
for n, ms in appincl.most_common(15):
    print("  %7.0f  %5.1f%%  %s" % (ms, 100 * ms / total, n[:110]))
print("\nself ms (top 12):")
for n, ms in selfw.most_common(12):
    print("  %7.0f  %5.1f%%  %s" % (ms, 100 * ms / total, n[:110]))

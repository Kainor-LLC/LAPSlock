#!/usr/bin/env python3
"""Self-tests for the Graph change watch. Offline: a small schema stands in for Graph's.

    python3 scripts/graph-watch/test_graph_watch.py
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import check_changelog  # noqa: E402
import check_schema  # noqa: E402
import report  # noqa: E402
import smoke  # noqa: E402

MINI = b"""<?xml version="1.0" encoding="utf-8"?>
<edmx:Edmx Version="4.0" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx"><edmx:DataServices>
<Schema Namespace="microsoft.graph" Alias="graph" xmlns="http://docs.oasis-open.org/odata/ns/edm">
  <EntityType Name="entity"><Key><PropertyRef Name="id"/></Key><Property Name="id" Type="Edm.String"/></EntityType>
  <EntityType Name="managedDevice" BaseType="graph.entity">
    <Property Name="deviceName" Type="Edm.String"/>
  </EntityType>
  <EntityType Name="deviceManagement" BaseType="graph.entity">
    <NavigationProperty Name="managedDevices" Type="Collection(graph.managedDevice)"/>
  </EntityType>
  <Action Name="wipe" IsBound="true"><Parameter Name="bindingParameter" Type="graph.managedDevice"/><Parameter Name="keepUserData" Type="Edm.Boolean"/></Action>
  <Function Name="report" IsBound="true"><Parameter Name="bindingParameter" Type="graph.managedDevice"/><ReturnType Type="Edm.String"/></Function>
  <EntityContainer Name="GraphService"><Singleton Name="deviceManagement" Type="graph.deviceManagement"/></EntityContainer>
</Schema></edmx:DataServices></edmx:Edmx>"""


class SchemaTests(unittest.TestCase):
    def setUp(self):
        self.schema = check_schema.Schema(MINI)

    def problems(self, **call):
        return check_schema.check_call(self.schema, call)

    def test_a_good_call_resolves(self):
        self.assertEqual(self.problems(path="/deviceManagement/managedDevices/{id}", method="GET", select=["id", "deviceName"]), [])
        self.assertEqual(self.problems(path="/deviceManagement/managedDevices/{id}/wipe", method="POST", parameters=["keepUserData"]), [])

    def test_a_missing_field_action_or_parameter_is_caught(self):
        self.assertTrue(self.problems(path="/deviceManagement/managedDevices/{id}", method="GET", select=["serialNumber"]))
        self.assertTrue(self.problems(path="/deviceManagement/managedDevices/{id}/retire", method="POST"))
        self.assertTrue(self.problems(path="/deviceManagement/managedDevices/{id}/wipe", method="POST", parameters=["keepEnrollmentData"]))
        self.assertTrue(self.problems(path="/nothing", method="GET"))

    def test_an_action_turned_function_is_caught(self):
        self.assertTrue(self.problems(path="/deviceManagement/managedDevices/{id}/report", method="POST"))
        self.assertTrue(self.problems(path="/deviceManagement/managedDevices/{id}/wipe", method="GET"))


class ChangelogTests(unittest.TestCase):
    T = {"managedDevice"}
    M = {"wipe", "keepUserData", "deviceName"}

    def test_flags_only_what_the_app_uses(self):
        flag = lambda s: check_changelog.sentence_breaks(s, self.T, self.M)
        self.assertTrue(flag("Removed the wipe method from the managedDevice resource."))
        self.assertTrue(flag("Deprecated the deviceName property on the managedDevice resource."))
        self.assertTrue(flag("Removed the managedDevice resource."))
        self.assertFalse(flag("Removed the bulkResize method from the managedDevice resource."))
        self.assertFalse(flag("Added the deviceName property to the managedDevice resource."))
        self.assertFalse(flag("Removed the wipe method from the cloudPC resource."))


class SmokeGuardTests(unittest.TestCase):
    def test_never_reads_a_secret_and_never_writes(self):
        for path in ["/directory/deviceLocalCredentials/x?$select=credentials",
                     "/informationProtection/bitlocker/recoveryKeys/x?$select=key",
                     "/informationProtection/bitlocker/recoveryKeys/x",
                     "/deviceManagement/managedDevices/x/retrieveDeviceLocalAdminAccountDetail",
                     "/me/authentication/temporaryAccessPassMethods"]:
            self.assertIsNotNone(smoke.refuse({"method": "GET", "path": "", "smoke": path}), path)
        self.assertIsNotNone(smoke.refuse({"method": "POST", "path": "", "smoke": "/me"}))
        self.assertIsNone(smoke.refuse({"method": "GET", "path": "", "smoke": "/directory/deviceLocalCredentials?$top=1"}))

    def test_the_manifest_smoke_reads_pass_the_guard(self):
        manifest = json.loads((Path(__file__).parent / "manifest.json").read_text())
        refused = [c["id"] for c in manifest["calls"] if c.get("smoke") and smoke.refuse(c)]
        self.assertEqual(refused, [])


class ReportTests(unittest.TestCase):
    def test_each_finding_is_reported_once(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "s.json").write_text(json.dumps([{"id": "a", "kit": "K", "problem": "gone"}]))
            (d / "k.json").write_text("[]")
            args = ["report.py", "--schema", str(d / "s.json"), "--known", str(d / "k.json"), "--out", str(d / "b.md")]
            report.main(args)
            body = (d / "b.md").read_text()
            self.assertIn("gone", body)
            (d / "k.json").write_text(json.dumps([{"body": body}]))
            (d / "b.md").unlink()
            report.main(args)
            self.assertFalse((d / "b.md").exists())


if __name__ == "__main__":
    unittest.main()

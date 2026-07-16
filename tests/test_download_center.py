"""
Tests for automation.download_center — MITRE ATT&CK Navigator layer export.
"""

import unittest

from automation.download_center import build_mitre_navigator_layer, extract_technique_ids


class TestExtractTechniqueIds(unittest.TestCase):
    def test_extracts_simple_technique_id(self):
        self.assertEqual(extract_technique_ids("Exploit Public-Facing Application (T1190)"), ["T1190"])

    def test_extracts_sub_technique_id(self):
        self.assertEqual(extract_technique_ids("PowerShell (T1059.001)"), ["T1059.001"])

    def test_extracts_multiple_and_dedupes(self):
        text = "Data Encrypted for Impact (T1486) / Inhibit System Recovery (T1490). Later mention of T1486 again."
        result = extract_technique_ids(text)
        self.assertEqual(result, ["T1486", "T1490"])

    def test_no_techniques_returns_empty(self):
        self.assertEqual(extract_technique_ids("No technique IDs in this text at all."), [])

    def test_ignores_non_technique_t_numbers(self):
        # T-shirt, T12 (too short), etc. must not match
        self.assertEqual(extract_technique_ids("A T12 reference and T-shirt mention."), [])


class TestBuildMitreNavigatorLayer(unittest.TestCase):
    def test_returns_none_when_no_techniques(self):
        self.assertIsNone(build_mitre_navigator_layer("No MITRE content here.", "Some Report"))

    def test_returns_valid_layer_structure(self):
        body = "Initial Access → Exploit Public-Facing Application (T1190): entry vector. Impact → Data Encrypted for Impact (T1486)."
        layer = build_mitre_navigator_layer(body, "Ransomware Report")
        self.assertEqual(layer["domain"], "enterprise-attack")
        technique_ids = [t["techniqueID"] for t in layer["techniques"]]
        self.assertIn("T1190", technique_ids)
        self.assertIn("T1486", technique_ids)

    def test_title_truncated_and_embedded(self):
        body = "Uses T1190 for initial access."
        layer = build_mitre_navigator_layer(body, "A" * 200)
        self.assertLessEqual(len(layer["name"]), 120)  # brand prefix + 80 char cap

    def test_all_techniques_have_required_navigator_fields(self):
        body = "T1190 and T1059.001 observed."
        layer = build_mitre_navigator_layer(body, "Report")
        for t in layer["techniques"]:
            self.assertIn("techniqueID", t)
            self.assertIn("color", t)
            self.assertIn("enabled", t)


if __name__ == "__main__":
    unittest.main()

"""
Tests for automation.industry_intelligence — detection and static profiles.
"""

import unittest

from automation.industry_intelligence import INDUSTRY_PROFILES, detect_industries, get_industry_profile


class TestDetectIndustries(unittest.TestCase):
    def test_healthcare_keywords_detected(self):
        result = detect_industries("Ransomware Hits Regional Hospital", "Patient records at the healthcare system were encrypted.")
        self.assertIn("healthcare", result)

    def test_finance_keywords_detected(self):
        result = detect_industries("Bank Suffers Data Breach", "A financial services company reported unauthorized access.")
        self.assertIn("finance", result)

    def test_no_industry_keywords_returns_empty(self):
        result = detect_industries("CVE-2026-9999 Critical RCE", "A critical remote code execution vulnerability.")
        self.assertEqual(result, [])

    def test_max_results_respected(self):
        result = detect_industries(
            "Attack Hits Hospital Bank Government School",
            "Healthcare hospital financial services federal agency university campus all affected.",
            max_results=2,
        )
        self.assertLessEqual(len(result), 2)

    def test_never_returns_more_than_detected(self):
        # Only healthcare keywords present — must not pad with other industries
        result = detect_industries("Hospital Ransomware Attack", "Patient data at risk in this healthcare incident.", max_results=5)
        self.assertEqual(result, ["healthcare"])


class TestIndustryProfiles(unittest.TestCase):
    def test_all_nine_industries_present(self):
        expected = {
            "healthcare", "finance", "government", "retail", "manufacturing",
            "critical_infrastructure", "energy", "technology", "education",
        }
        self.assertEqual(set(INDUSTRY_PROFILES.keys()), expected)

    def test_every_profile_has_required_fields(self):
        required = {"name", "risk_profile", "common_targets", "attack_paths", "compliance_mapping", "priority_actions", "services"}
        for key, profile in INDUSTRY_PROFILES.items():
            missing = required - set(profile.keys())
            self.assertFalse(missing, f"{key} missing fields: {missing}")

    def test_get_industry_profile_returns_empty_dict_for_unknown(self):
        self.assertEqual(get_industry_profile("nonexistent"), {})

    def test_get_industry_profile_returns_real_profile(self):
        profile = get_industry_profile("healthcare")
        self.assertEqual(profile["name"], "Healthcare")
        self.assertIn("HIPAA", profile["compliance_mapping"])


if __name__ == "__main__":
    unittest.main()

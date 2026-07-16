"""
Tests for automation.product_recommendations — data-driven service matching.
"""

import unittest

from automation.product_recommendations import SERVICES, recommend_services, top_recommendation


class TestRecommendServices(unittest.TestCase):
    def test_ransomware_recommends_incident_response(self):
        result = recommend_services(["Ransomware"])
        names = [s["name"] for s in result]
        self.assertIn("Incident Response", names)

    def test_ai_security_recommends_ai_assessment(self):
        result = recommend_services(["AI Security"])
        names = [s["name"] for s in result]
        self.assertIn("AI Security Assessment", names)

    def test_vulnerabilities_recommends_vulnerability_assessment(self):
        result = recommend_services(["Vulnerabilities"])
        names = [s["name"] for s in result]
        self.assertIn("Vulnerability Assessment", names)

    def test_no_matching_labels_falls_back_to_threat_intelligence(self):
        result = recommend_services(["CYBERDUDEBIVASH", "Threat Intelligence"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "Threat Intelligence")

    def test_empty_labels_falls_back_to_default(self):
        result = recommend_services([])
        self.assertEqual(result[0]["name"], "Threat Intelligence")

    def test_max_results_respected(self):
        result = recommend_services(["Ransomware", "CISA KEV", "APT", "AI Security"], max_results=2)
        self.assertLessEqual(len(result), 2)

    def test_no_duplicate_services_across_multiple_matching_labels(self):
        result = recommend_services(["Ransomware", "Malware Research"], max_results=5)
        names = [s["name"] for s in result]
        self.assertEqual(len(names), len(set(names)))

    def test_all_service_dicts_have_name_and_description(self):
        for key, svc in SERVICES.items():
            self.assertIn("name", svc, f"{key} missing name")
            self.assertIn("description", svc, f"{key} missing description")


class TestTopRecommendation(unittest.TestCase):
    def test_returns_none_for_empty_labels(self):
        self.assertIsNone(top_recommendation([]))

    def test_returns_single_service_for_matching_label(self):
        result = top_recommendation(["Ransomware"])
        self.assertIsNotNone(result)
        self.assertIn("name", result)


if __name__ == "__main__":
    unittest.main()

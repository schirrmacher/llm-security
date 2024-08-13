import json
import unittest
import tempfile

from security_army_knife.analysis.cve_analysis import (
    CVE,
    CVEAnalysis,
    CVECategory,
)
from security_army_knife.analysis.infrastructure_analysis import (
    InfrastructureAnalysis,
)


class TestCVE(unittest.TestCase):

    def setUp(self):
        # Sample data for a CVE instance
        self.cve_data = {
            "name": "CVE-2023-4911",
            "description": "A buffer overflow was discovered...",
            "category": "distro",
            "code_analysis": None,
            "api_spec_analysis": None,
            "architecture_analysis": None,
            "final_analysis": None,
        }
        self.cve_instance = CVE.from_json(self.cve_data)

    def test_cve_initialization(self):
        cve = CVE(
            name="CVE-2023-4911",
            description="A buffer overflow was discovered...",
            category=CVECategory.distro,
        )
        self.assertEqual(cve.name, "CVE-2023-4911")
        self.assertEqual(cve.description, "A buffer overflow was discovered...")
        self.assertEqual(cve.category, CVECategory.distro)
        self.assertIsNone(cve.code_analysis)
        self.assertIsNone(cve.api_spec_analysis)
        self.assertIsNone(cve.architecture_analysis)
        self.assertIsNone(cve.final_analysis)

    def test_cve_from_json(self):
        self.assertEqual(self.cve_instance.name, self.cve_data["name"])
        self.assertEqual(
            self.cve_instance.description, self.cve_data["description"]
        )
        self.assertEqual(self.cve_instance.category, self.cve_data["category"])

    def test_cve_to_json(self):
        cve_json = self.cve_instance.to_json()
        self.assertEqual(cve_json["name"], self.cve_data["name"])
        self.assertEqual(cve_json["description"], self.cve_data["description"])
        self.assertEqual(cve_json["category"], self.cve_data["category"])


class TestCVEAnalysis(unittest.TestCase):

    def setUp(self):
        self.infrastructure_data = {
            "components": [
                {
                    "name": "Web Server",
                    "type": "Server",
                    "public": True,
                    "explanation": "Handles HTTP requests.",
                    "configurations": ["SSL enabled", "Firewall rules applied"],
                    "ports": ["80", "443"],
                    "protocols": ["HTTP", "HTTPS"],
                },
                {
                    "name": "Database",
                    "type": "DB",
                    "public": False,
                    "explanation": "Stores user data.",
                },
            ]
        }
        self.cve_list_data = [
            {
                "name": "CVE-2023-4911",
                "description": "A buffer overflow was discovered...",
                "category": "distro",
                "code_analysis": None,
                "api_spec_analysis": None,
                "architecture_analysis": None,
                "final_analysis": None,
            },
            {
                "name": "CVE-2022-3509",
                "description": "A parsing issue similar to CVE-2022-3171...",
                "category": "app",
                "code_analysis": {
                    "queries": ["\\btextformat\\b"],
                    "affected_files": ["file1.java"],
                },
                "api_spec_analysis": {
                    "facilitates_attack": False,
                    "explanation": "Explanation text",
                },
                "architecture_analysis": {
                    "infrastructure_conditions": ["Condition1", "Condition2"]
                },
                "final_analysis": {
                    "critical": False,
                    "summary": "Summary text",
                    "threat_scenarios": ["Scenario 1", "Scenario 2"],
                },
            },
        ]
        self.infrastructure_analysis_instance = (
            InfrastructureAnalysis.from_json(self.infrastructure_data)
        )
        self.cve_analysis_instance = CVEAnalysis.from_json(
            {
                "cves": self.cve_list_data,
                "infrastructure_analysis": self.infrastructure_data,
            }
        )

    def test_cve_analysis_initialization(self):
        cve_analysis = CVEAnalysis(
            cves=[CVE.from_json(cve) for cve in self.cve_list_data],
            infrastructure_analysis=self.infrastructure_analysis_instance,
        )
        self.assertEqual(len(cve_analysis.cves), 2)
        self.assertEqual(cve_analysis.cves[0].name, "CVE-2023-4911")
        self.assertIsNotNone(cve_analysis.infrastructure_analysis)
        self.assertEqual(
            len(cve_analysis.infrastructure_analysis.components), 2
        )

    def test_cve_analysis_from_json(self):
        self.assertEqual(len(self.cve_analysis_instance.cves), 2)
        self.assertEqual(
            self.cve_analysis_instance.cves[0].name, "CVE-2023-4911"
        )
        self.assertIsNotNone(self.cve_analysis_instance.infrastructure_analysis)
        self.assertEqual(
            len(self.cve_analysis_instance.infrastructure_analysis.components),
            2,
        )

    def test_cve_analysis_to_json(self):
        cve_analysis_json = self.cve_analysis_instance.to_json()
        self.assertEqual(len(cve_analysis_json["cves"]), 2)
        self.assertEqual(cve_analysis_json["cves"][0]["name"], "CVE-2023-4911")
        self.assertIn("infrastructure_analysis", cve_analysis_json)
        self.assertEqual(
            len(cve_analysis_json["infrastructure_analysis"]["components"]), 2
        )

    def test_save_to_file(self):
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".json"
        ) as temp_file:
            file_path = temp_file.name
            self.cve_analysis_instance.save_to_file(file_path)

        with open(file_path, "r") as file:
            data = json.load(file)

        self.assertEqual(len(data["cves"]), 2)
        self.assertEqual(data["cves"][0]["name"], "CVE-2023-4911")
        self.assertIn("infrastructure_analysis", data)
        self.assertEqual(len(data["infrastructure_analysis"]["components"]), 2)

    def test_load_and_merge_state(self):
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".json"
        ) as temp_file:
            file_path = temp_file.name
            # Assuming the file is saved previously as in the save_to_file test
            self.cve_analysis_instance.save_to_file(file_path)

        new_cves = [
            CVE.from_json(
                {
                    "name": "CVE-2023-9999",
                    "description": "A new CVE.",
                    "category": "os",
                }
            )
        ]
        cve_analysis = CVEAnalysis.load_and_merge_state(file_path, new_cves)

        self.assertEqual(len(cve_analysis.cves), 3)
        self.assertEqual(cve_analysis.cves[2].name, "CVE-2022-3509")
        self.assertIsNotNone(cve_analysis.infrastructure_analysis)
        self.assertEqual(
            len(cve_analysis.infrastructure_analysis.components), 2
        )


if __name__ == "__main__":
    unittest.main()

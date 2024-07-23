import unittest
import json
import os
from unittest.mock import MagicMock
from security_army_knife.analysis.code_analysis import CodeAnalysis
from security_army_knife.analysis.cve import (
    CVE,
    CVECategory,
)


class TestCVE(unittest.TestCase):

    def setUp(self):
        # Create a mock CodeAnalysis object
        self.mock_code_analysis = MagicMock(spec=CodeAnalysis)
        self.mock_code_analysis.to_json.return_value = {"mock": "data"}
        self.mock_code_analysis.__str__.return_value = "Mock Code Analysis"

        # Example CVE data
        self.cve_data = {
            "name": "CVE-1234",
            "description": "Example CVE",
            "category": CVECategory.os,
            "code_analysis": {"mock": "data"},
        }

        self.new_cve_data = {
            "name": "CVE-5678",
            "description": "New CVE",
            "category": CVECategory.app,
            "code_analysis": {"mock": "new data"},
        }

        # File path for testing persistence
        self.file_path = "test_cve_state.json"

    def tearDown(self):
        # Clean up the test file if it exists
        if os.path.exists(self.file_path):
            os.remove(self.file_path)

    def test_cve_initialization(self):
        cve = CVE(
            name="CVE-1234",
            description="Example CVE",
            category=CVECategory.os,
            code_analysis=self.mock_code_analysis,
        )

        self.assertEqual(cve.name, "CVE-1234")
        self.assertEqual(cve.description, "Example CVE")
        self.assertEqual(cve.category, CVECategory.os)
        self.assertEqual(cve.code_analysis, self.mock_code_analysis)

    def test_cve_from_json(self):
        # Mock the from_json method of CodeAnalysis
        CodeAnalysis.from_json = MagicMock(return_value=self.mock_code_analysis)

        cve = CVE.from_json(self.cve_data)

        self.assertEqual(cve.name, "CVE-1234")
        self.assertEqual(cve.description, "Example CVE")
        self.assertEqual(cve.category, CVECategory.os)
        self.assertEqual(cve.code_analysis, self.mock_code_analysis)

    def test_cve_to_json(self):
        cve = CVE(
            name="CVE-1234",
            description="Example CVE",
            category=CVECategory.os,
            code_analysis=self.mock_code_analysis,
        )

        expected_json = {
            "name": "CVE-1234",
            "description": "Example CVE",
            "category": CVECategory.os,
            "code_analysis": {"mock": "data"},
        }

        self.assertEqual(cve.to_json(), expected_json)

    def test_cve_persist_state(self):
        cve = CVE(
            name="CVE-1234",
            description="Example CVE",
            category=CVECategory.os,
            code_analysis=self.mock_code_analysis,
        )

        CVE.persist_state([cve], self.file_path)

        with open(self.file_path, "r") as file:
            data = json.load(file)

        self.assertEqual(data, [cve.to_json()])

    def test_cve_load_state(self):
        cve = CVE(
            name="CVE-1234",
            description="Example CVE",
            category=CVECategory.os,
            code_analysis=self.mock_code_analysis,
        )

        with open(self.file_path, "w") as file:
            json.dump([cve.to_json()], file, indent=4)

        loaded_cves = CVE.load_state(self.file_path)

        self.assertEqual(len(loaded_cves), 1)
        self.assertEqual(loaded_cves[0].name, "CVE-1234")
        self.assertEqual(loaded_cves[0].description, "Example CVE")
        self.assertEqual(loaded_cves[0].category, CVECategory.os)
        self.assertEqual(
            loaded_cves[0].code_analysis.to_json(), {"mock": "data"}
        )

    def test_merge_cves(self):
        cve1 = CVE.from_json(self.cve_data)
        cve2 = CVE.from_json(self.new_cve_data)

        merged_cves = CVE.merge_cves([cve1], [cve2])

        self.assertEqual(len(merged_cves), 2)
        self.assertEqual(merged_cves[0].name, "CVE-5678")
        self.assertEqual(merged_cves[1].name, "CVE-1234")

    def test_load_and_merge_state(self):
        cve1 = CVE.from_json(self.cve_data)
        new_cve = CVE.from_json(self.new_cve_data)

        # Persist initial state
        CVE.persist_state([cve1], self.file_path)

        # Load and merge new CVEs
        merged_cves = CVE.load_and_merge_state(self.file_path, [new_cve])

        self.assertEqual(len(merged_cves), 2)
        self.assertEqual(merged_cves[0].name, "CVE-5678")
        self.assertEqual(merged_cves[1].name, "CVE-1234")

        with open(self.file_path, "r") as file:
            data = json.load(file)

        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]["name"], "CVE-5678")
        self.assertEqual(data[1]["name"], "CVE-1234")


if __name__ == "__main__":
    unittest.main()

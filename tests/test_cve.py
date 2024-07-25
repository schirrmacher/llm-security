import os
import json
import unittest

from unittest.mock import MagicMock
from security_army_knife.analysis.api_spec_analysis import APISpecAnalysis
from security_army_knife.analysis.code_analysis import CodeAnalysis
from security_army_knife.analysis.cve import (
    CVE,
    CVECategory,
)


class TestCVE(unittest.TestCase):

    def setUp(self):
        self.file_path = "test_cve_state.json"

        self.mock_code_analysis = CodeAnalysis(
            queries=["query1"], affected_files=["file1"]
        )
        self.mock_code_analysis_json = self.mock_code_analysis.to_json()

        self.cve_data = {
            "name": "CVE-1234",
            "description": "Example CVE",
            "category": CVECategory.os,
            "code_analysis": self.mock_code_analysis_json,
        }

        self.new_cve_data = {
            "name": "CVE-5678",
            "description": "Another CVE",
            "category": CVECategory.app,
            "code_analysis": {
                "queries": ["query2"],
                "affected_files": ["file2"],
            },
        }

    def tearDown(self):
        if os.path.exists(self.file_path):
            os.remove(self.file_path)

    def test_code_analysis(self):
        # Test initialization
        code_analysis = CodeAnalysis(
            queries=["query1", "query2"], affected_files=["file1", "file2"]
        )
        self.assertEqual(code_analysis.queries, ["query1", "query2"])
        self.assertEqual(code_analysis.affected_files, ["file1", "file2"])

        # Test from_json method
        json_data = {"queries": ["query3"], "affected_files": ["file3"]}
        code_analysis_from_json = CodeAnalysis.from_json(json_data)
        self.assertEqual(code_analysis_from_json.queries, ["query3"])
        self.assertEqual(code_analysis_from_json.affected_files, ["file3"])

        # Test to_json method
        self.assertEqual(code_analysis_from_json.to_json(), json_data)

        # Test __str__ method
        self.assertEqual(
            str(code_analysis),
            "Code Analysis:\n  Queries: query1, query2\n  Affected Files: file1, file2",
        )

    def test_api_spec_analysis(self):
        # Test initialization
        api_spec_analysis = APISpecAnalysis(
            critical=True, explanation="Critical issue found"
        )
        self.assertTrue(api_spec_analysis.critical)
        self.assertEqual(api_spec_analysis.explanation, "Critical issue found")

        # Test from_json method
        json_data = {"critical": False, "explanation": "Minor issue"}
        api_spec_from_json = APISpecAnalysis.from_json(json_data)
        self.assertFalse(api_spec_from_json.critical)
        self.assertEqual(api_spec_from_json.explanation, "Minor issue")

        # Test to_json method
        self.assertEqual(api_spec_from_json.to_json(), json_data)

        # Test __str__ method
        self.assertEqual(
            str(api_spec_analysis),
            "API Spec Analysis:\n  Critical: True\n  Explanation: Critical issue found",
        )

    def test_cve(self):
        # Test initialization
        code_analysis = CodeAnalysis(
            queries=["query1"], affected_files=["file1"]
        )
        api_spec_analysis = APISpecAnalysis(
            critical=False, explanation="No critical issues"
        )
        cve = CVE(
            name="CVE-1234",
            description="Test CVE",
            category=CVECategory.os,
            code_analysis=code_analysis,
            api_spec_analysis=api_spec_analysis,
        )
        self.assertEqual(cve.name, "CVE-1234")
        self.assertEqual(cve.description, "Test CVE")
        self.assertEqual(cve.category, CVECategory.os)
        self.assertEqual(cve.code_analysis, code_analysis)
        self.assertEqual(cve.api_spec_analysis, api_spec_analysis)

        # Test from_json method
        json_data = {
            "name": "CVE-5678",
            "description": "Another CVE",
            "category": CVECategory.app,
            "code_analysis": {
                "queries": ["query2"],
                "affected_files": ["file2"],
            },
            "api_spec_analysis": {
                "critical": True,
                "explanation": "Critical issue found",
            },
        }
        cve_from_json = CVE.from_json(json_data)
        self.assertEqual(cve_from_json.name, "CVE-5678")
        self.assertEqual(cve_from_json.description, "Another CVE")
        self.assertEqual(cve_from_json.category, CVECategory.app)
        self.assertEqual(cve_from_json.code_analysis.queries, ["query2"])
        self.assertEqual(cve_from_json.code_analysis.affected_files, ["file2"])
        self.assertTrue(cve_from_json.api_spec_analysis.critical)
        self.assertEqual(
            cve_from_json.api_spec_analysis.explanation, "Critical issue found"
        )

        # Test to_json method
        self.assertEqual(cve_from_json.to_json(), json_data)

        # Test __str__ method
        self.assertEqual(
            str(cve),
            "CVE Name: CVE-1234\nDescription: Test CVE\nCategory: os\n"
            "Code Analysis:\n  Queries: query1\n  Affected Files: file1\n"
            "API Spec Analysis:\n  Critical: False\n  Explanation: No critical issues",
        )

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
            loaded_cves[0].code_analysis.to_json(), self.mock_code_analysis_json
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

import unittest
import os
import json

from security_army_knife.application_agent import ApplicationCVE
from security_army_knife.cve_categorizer_agent import (
    CategorizedCVE,
    CVECategory,
)
from security_army_knife.state_handler import StateHandler


class TestStateHandler(unittest.TestCase):
    def setUp(self):
        self.file_path = "test_state.json"
        self.state_handler = StateHandler(self.file_path)

    def tearDown(self):
        if os.path.exists(self.file_path):
            os.remove(self.file_path)

    def test_store_and_retrieve_categorized_cves(self):
        cve1 = CategorizedCVE(
            "CVE-2023-0001", "Description for CVE-2023-0001", True, "Category1"
        )
        cve2 = CategorizedCVE(
            "CVE-2023-0002", "Description for CVE-2023-0002", False, "Category2"
        )

        self.state_handler.store_categorized_cves([cve1, cve2])
        categorized_cves = self.state_handler.get_categorized_cves()

        self.assertEqual(len(categorized_cves), 2)
        self.assertEqual(categorized_cves[0].name, "CVE-2023-0001")
        self.assertEqual(categorized_cves[1].name, "CVE-2023-0002")

    def test_store_and_retrieve_application_cves(self):
        app_cve1 = ApplicationCVE(
            "CVE-2023-0003",
            "Description for CVE-2023-0003",
            True,
            CVECategory.app,
            ["query1", "query2"],
        )
        app_cve2 = ApplicationCVE(
            "CVE-2023-0004",
            "Description for CVE-2023-0004",
            False,
            CVECategory.os,
            ["query3"],
        )

        self.state_handler.store_application_cves([app_cve1, app_cve2])
        application_cves = self.state_handler.get_application_cves()

        self.assertEqual(len(application_cves), 2)
        self.assertEqual(application_cves[0].name, "CVE-2023-0003")
        self.assertEqual(application_cves[1].name, "CVE-2023-0004")

    def test_load_data_from_existing_file(self):
        data = {
            "categorized_cves": [
                {
                    "name": "CVE-2023-0001",
                    "description": "Description for CVE-2023-0001",
                    "urgent": True,
                    "category": "Category1",
                },
                {
                    "name": "CVE-2023-0002",
                    "description": "Description for CVE-2023-0002",
                    "urgent": False,
                    "category": "Category2",
                },
            ],
            "application_cves": [
                {
                    "name": "CVE-2023-0003",
                    "description": "Description for CVE-2023-0003",
                    "urgent": True,
                    "category": "application",
                    "code_queries": ["query1", "query2"],
                },
                {
                    "name": "CVE-2023-0004",
                    "description": "Description for CVE-2023-0004",
                    "urgent": False,
                    "category": "application",
                    "code_queries": ["query3"],
                },
            ],
        }
        with open(self.file_path, "w") as file:
            json.dump(data, file, indent=4)

        self.state_handler.load_data()
        categorized_cves = self.state_handler.get_categorized_cves()
        application_cves = self.state_handler.get_application_cves()

        self.assertEqual(len(categorized_cves), 2)
        self.assertEqual(len(application_cves), 2)
        self.assertEqual(categorized_cves[0].name, "CVE-2023-0001")
        self.assertEqual(application_cves[0].name, "CVE-2023-0003")


if __name__ == "__main__":
    unittest.main()

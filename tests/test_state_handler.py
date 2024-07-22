import unittest
import json
from unittest.mock import mock_open, patch

from security_army_knife.agents.source_code_agent import CVE
from security_army_knife.agents.cve_categorizer import (
    CVE,
    CVECategory,
)
from security_army_knife.cve import CVE
from security_army_knife.state_handler import StateHandler


class TestStateHandler(unittest.TestCase):
    input_cves = [
        CVE(
            name="CVE-2023-34054",
            description="In Reactor Netty HTTP Server, versions 1.1.x prior to 1.1.13 and versions 1.0.x prior to 1.0.39, it is possible for a user to provide specially crafted HTTP requests that may cause a denial-of-service (DoS) condition. Specifically, an application is vulnerable if Reactor Netty HTTP Server built-in integration with Micrometer is enabled.",
        ),
        CVE(
            name="CVE-2022-1471",
            description="SnakeYaml's Constructor() class does not restrict types which can be instantiated during deserialization. Deserializing yaml content provided by an attacker can lead to remote code execution. We recommend using SnakeYaml's SafeConsturctor when parsing untrusted content to restrict deserialization. We recommend upgrading to version 2.0 and beyond.",
        ),
        CVE(
            name="CVE-2023-0001",
            description="Description for CVE-2023-0001",
        ),
    ]

    state = {
        "categorized_cves": [
            {
                "name": "CVE-2023-0001",
                "description": "Description for CVE-2023-0001",
                "category": "Category1",
            },
            {
                "name": "CVE-2023-0002",
                "description": "Description for CVE-2023-0002",
                "category": "Category2",
            },
        ],
        "application_cves": [
            {
                "name": "CVE-2023-0003",
                "description": "Description for CVE-2023-0003",
                "category": "application",
                "code_queries": ["query1", "query2"],
            },
            {
                "name": "CVE-2023-0004",
                "description": "Description for CVE-2023-0004",
                "category": "application",
                "code_queries": ["query3"],
            },
        ],
    }

    @patch("builtins.open", new_callable=mock_open, read_data=json.dumps(state))
    def test_load_data_from_existing_file(self, mock_file):
        state_handler = StateHandler("dummypath.json", self.input_cves)

        categorized_cves = state_handler.get_cves_to_be_categorized()
        self.assertEqual(categorized_cves[0].name, "CVE-2023-34054")
        self.assertEqual(categorized_cves[1].name, "CVE-2022-1471")
        self.assertEqual(len(categorized_cves), 2)

        application_cves = state_handler.get_application_cves_to_be_analyzed()
        self.assertEqual(application_cves[0].name, "CVE-2023-0001")
        self.assertEqual(application_cves[1].name, "CVE-2023-0002")
        self.assertEqual(len(application_cves), 2)

        all_application_cves = state_handler.store_application_cves(
            application_cves
        )
        self.assertEqual(all_application_cves[0].name, "CVE-2023-0003")
        self.assertEqual(all_application_cves[1].name, "CVE-2023-0004")
        self.assertEqual(all_application_cves[2].name, "CVE-2023-0001")
        self.assertEqual(all_application_cves[3].name, "CVE-2023-0002")
        self.assertEqual(len(all_application_cves), 4)

    @patch("builtins.open", new_callable=mock_open, read_data=json.dumps(state))
    def test_store_categorized_cves(self, mock_file):
        state_handler = StateHandler("dummypath.json", self.input_cves)
        new_categorized_cves = []

        for cve in self.input_cves:
            new_categorized_cves.append(
                CVE(
                    name=cve.name,
                    description=cve.description,
                    category=CVECategory.app,
                ),
            )

        all_categorized_cves = state_handler.store_categorized_cves(
            new_categorized_cves
        )
        self.assertEqual(all_categorized_cves[0].name, "CVE-2023-0001")
        self.assertEqual(all_categorized_cves[1].name, "CVE-2023-0002")
        self.assertEqual(all_categorized_cves[2].name, "CVE-2023-34054")
        self.assertEqual(all_categorized_cves[3].name, "CVE-2022-1471")
        self.assertEqual(len(all_categorized_cves), 4)

    @patch("builtins.open", new_callable=mock_open, read_data=json.dumps(state))
    def test_store_application_cves(self, mock_file):
        state_handler = StateHandler("dummypath.json", self.input_cves)
        new_application_cves = []

        for cve in self.input_cves:
            new_application_cves.append(
                CVE(
                    name=cve.name,
                    description=cve.description,
                    category=CVECategory.app,
                ),
            )

        self.assertEqual(self.input_cves[0].name, "CVE-2023-34054")
        self.assertEqual(self.input_cves[1].name, "CVE-2022-1471")
        self.assertEqual(self.input_cves[2].name, "CVE-2023-0001")
        self.assertEqual(len(self.input_cves), 3)

        all_application_cves = state_handler.store_categorized_cves(
            new_application_cves
        )
        self.assertEqual(all_application_cves[0].name, "CVE-2023-0001")
        self.assertEqual(all_application_cves[1].name, "CVE-2023-0002")
        self.assertEqual(all_application_cves[2].name, "CVE-2023-34054")
        self.assertEqual(all_application_cves[3].name, "CVE-2022-1471")
        self.assertEqual(len(all_application_cves), 4)


if __name__ == "__main__":
    unittest.main()

import json

import unittest
from unittest.mock import patch, MagicMock

from security_army_knife.cve import CVE, CVECategory
from security_army_knife.agents.cve_categorizer import CVECategorizerAgent


class TestCVECategorizerAgent(unittest.TestCase):

    @patch("security_army_knife.agents.base_agent.BaseAgent.model", create=True)
    def test_categorize(self, mock_model):
        # Create a mock response from the model
        mock_response = MagicMock()
        mock_response.message.content = json.dumps(
            {
                "name": "CVE-1234-5678",
                "description": "Test CVE description",
                "category": CVECategory.os,
            }
        )
        mock_model.talk.return_value = mock_response

        # Create a CVE instance to categorize
        cve = CVE(
            name="CVE-1234-5678",
            description="Test CVE description",
        )

        # Instantiate the agent and categorize the CVE
        agent = CVECategorizerAgent(model=mock_model)
        categorized_cves = agent.analyze([cve])

        # Check the result
        self.assertEqual(len(categorized_cves), 1)
        categorized_cve = categorized_cves[0]
        self.assertEqual(categorized_cve.name, "CVE-1234-5678")
        self.assertEqual(categorized_cve.description, "Test CVE description")
        self.assertEqual(categorized_cve.category, CVECategory.os)

        # Ensure the mock model's talk method was called once
        self.assertEqual(mock_model.talk.call_count, 1)

    @patch("security_army_knife.agents.base_agent.BaseAgent.model", create=True)
    def test_categorize_with_parsing_error(self, mock_model):
        # Create a mock response that causes a JSON parsing error
        mock_response = MagicMock()
        mock_response.message.content = "Invalid JSON"
        mock_model.talk.return_value = mock_response

        # Create a CVE instance to categorize
        cve = CVE(
            name="CVE-1234-5678",
            description="Test CVE description",
        )

        # Instantiate the agent and categorize the CVE
        agent = CVECategorizerAgent(model=mock_model)
        categorized_cves = agent.analyze([cve])

        # Check the result
        self.assertEqual(len(categorized_cves), 1)
        categorized_cve = categorized_cves[0]
        self.assertEqual(categorized_cve.name, "CVE-1234-5678")
        self.assertEqual(categorized_cve.description, "Test CVE description")
        self.assertEqual(categorized_cve.category, CVECategory.unknown)

        # Ensure the mock model's talk method was called once
        self.assertEqual(mock_model.talk.call_count, 1)


if __name__ == "__main__":
    unittest.main()

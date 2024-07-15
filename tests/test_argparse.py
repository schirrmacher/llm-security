import unittest
from unittest.mock import patch

import sys
import os

# Find the CLI module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security_army_knife.cli import parse_arguments


class TestParseArguments(unittest.TestCase):

    @patch(
        "argparse._sys.argv",
        [
            "program_name",
            "-cve",
            "tests/files/log4j.txt",
            "-arc",
            "tests/files/api-gateway.d2",
            "-dep",
            "tests/files/sbom.json",
            "-llm",
            "Mistral",
            "-o",
            "severity",
            "-of",
            "json",
        ],
    )
    def test_parse_arguments(self):

        args = parse_arguments()

        self.assertEqual(
            simplify_string(args.cve_description.read()),
            "Apache Log4j2 2.0-beta9 throug",
        )
        self.assertEqual(
            simplify_string(args.architecture_diagram.read()),
            "vars: {  d2-config: {    layou",
        )
        self.assertEqual(
            simplify_string(args.dependency_list.read()),
            '{    "spdxVersion": "SPDX-2.3"',
        )
        self.assertEqual(args.large_language_model, "Mistral")
        self.assertEqual(args.output, "severity")
        self.assertEqual(args.output_format, "json")


def simplify_string(str):
    return str.replace("\n", "")[:30]


if __name__ == "__main__":
    unittest.main()

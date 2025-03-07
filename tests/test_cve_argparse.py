import unittest
import argparse
from unittest.mock import patch

from security_army_knife.commands.cve import add_subcommand as add_cve_parser


class TestParseArguments(unittest.TestCase):

    @patch(
        "argparse._sys.argv",
        [
            "program_name",
            "cve",
            "-cve",
            "tests/files/cve-advisories.json",
            "-arc",
            "tests/files/api-gateway.d2",
            "-dep",
            "tests/files/sbom.json",
            "-llm",
            "mistral",
            "-o",
            "severity",
            "-of",
            "json",
            "-api",
            "tests/files/swagger-open-api.json",
            "-src",
            "tests/files",
        ],
    )
    def test_parse_arguments(self):

        parser = argparse.ArgumentParser(
            description="Security Army Knife - AI for security day to day tasks"
        )

        subparsers = parser.add_subparsers(dest="command", help="Subcommands")
        add_cve_parser(subparsers)

        args = parser.parse_args()

        self.assertEqual(args.cve_list, "tests/files/cve-advisories.json")
        self.assertEqual(
            simplify_string(args.architecture_diagram.read()),
            "vars: {  d2-config: {    layou",
        )
        self.assertEqual(
            simplify_string(args.dependency_list.read()),
            '{    "spdxVersion": "SPDX-2.3"',
        )
        self.assertEqual(
            simplify_string(args.api_documentation.read()),
            '{"components":{"schemas":{"Act',
        )
        self.assertEqual(args.source_code, "tests/files")
        self.assertEqual(args.large_language_model, "mistral")
        self.assertEqual(args.output, "severity")
        self.assertEqual(args.output_format, "json")


def simplify_string(str):
    return str.replace("\n", "")[:30]


if __name__ == "__main__":
    unittest.main()

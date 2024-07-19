import unittest
from unittest.mock import patch

from security_army_knife.cli import parse_arguments


class TestParseArguments(unittest.TestCase):

    @patch(
        "argparse._sys.argv",
        [
            "program_name",
            "-cve",
            "tests/files/cve-advisories.json",
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
            "-api",
            "tests/files/swagger-open-api.json",
            "-src",
            "tests/files",
        ],
    )
    def test_parse_arguments(self):

        args = parse_arguments()

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
        self.assertEqual(args.large_language_model, "Mistral")
        self.assertEqual(args.output, "severity")
        self.assertEqual(args.output_format, "json")


def simplify_string(str):
    return str.replace("\n", "")[:30]


if __name__ == "__main__":
    unittest.main()

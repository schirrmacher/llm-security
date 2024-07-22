import os
import json
import logging
import argparse

from typing import TextIO, Optional

from security_army_knife.mistral_model import MistralModel
from security_army_knife.base_model import BaseModel
from security_army_knife.application_agent import ApplicationAgent
from security_army_knife.cve_categorizer_agent import (
    CVECategorizerAgent,
    CVECategory,
    CategorizedCVE,
)
from security_army_knife.trivy_importer import TrivyImporter
from security_army_knife.cve import CVE
from security_army_knife.state_handler import StateHandler

ASCII_ART = """
░█▀▀░█▀▀░█▀▀░█░█░█▀▄░▀█▀░▀█▀░█░█░░░█▀█░█▀▄░█▄█░█░█░░░█░█░█▀█░▀█▀░█▀▀░█▀▀
░▀▀█░█▀▀░█░░░█░█░█▀▄░░█░░░█░░░█░░░░█▀█░█▀▄░█░█░░█░░░░█▀▄░█░█░░█░░█▀▀░█▀▀
░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░░▀░░░▀░░░░▀░▀░▀░▀░▀░▀░░▀░░░░▀░▀░▀░▀░▀▀▀░▀░░░▀▀▀
"""


def setup_logging(log_level):
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
    )
    logger = logging.getLogger("SecurityArmyKnife")
    logger.info(ASCII_ART)


def run_security_army_knife(
    cve_file_path: Optional[str],
    trivy_file_path: Optional[str],
    architecture_diagram: Optional[TextIO],
    dependency_list: Optional[TextIO],
    api_documentation: Optional[TextIO],
    source_code: Optional[str],
    state_file_path: Optional[str],
    large_language_model: str,
    output_option: str,
    output_format: str,
) -> int:
    logger = logging.getLogger("SecurityArmyKnife")

    model: BaseModel
    if large_language_model == "Mistral":
        model = MistralModel()
    else:
        raise ValueError(f"{large_language_model} not supported.")

    try:
        if trivy_file_path:
            with open(trivy_file_path, "r") as file:
                advisories = file.read()
                cves = TrivyImporter(trivy_file_path).get_cves()
        elif cve_file_path:
            with open(cve_file_path, "r") as file:
                advisories = json.loads(file.read())
                cves = CVE.from_json_list(advisories)

    except Exception as e:
        raise ValueError(f"There are issues with parsing CVEs from: {e}")

    state = StateHandler(state_file_path, input_cves=cves)

    ### CATEGORIZE STAGE ###
    categorizer = CVECategorizerAgent(model)
    to_be_categorized: list[CVE] = state.get_cves_to_be_categorized()
    categorized_cves: list[CategorizedCVE] = categorizer.categorize(
        cves=to_be_categorized
    )
    all_categorized_cves = state.store_categorized_cves(categorized_cves)

    for cve in all_categorized_cves:
        logger.info(f"Categorized: {cve.name} => {cve.category}")

    ### ANALYZE APPLICATION CVEs STAGE ###
    app_cve_analyzer = ApplicationAgent(model)
    analyzed_app_cves = state.get_application_cves_to_be_analyzed()
    to_be_analyzed = [
        e for e in analyzed_app_cves if e.category == CVECategory.app
    ]
    analyzed_app_cves = app_cve_analyzer.categorize(cves=to_be_analyzed)
    all_application_cves = state.store_application_cves(analyzed_app_cves)

    for cve in all_application_cves:
        logger.info(f"Analyzed: {cve.name} => {cve.code_queries}")

    return 0


def is_valid_directory(path):
    """Check if the given path is a valid directory."""
    if not os.path.isdir(path):
        raise argparse.ArgumentTypeError(f"'{path}' is not a valid directory.")
    return path


def is_valid_file(path):
    """Check if the given path is a valid directory."""
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError(f"'{path}' is not a valid file.")
    return path


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Analyze CVEs to accelerate decisions."
    )

    # Creating argument groups
    input_group = parser.add_argument_group(
        "input files", "Input files required for analysis"
    )
    output_group = parser.add_argument_group(
        "output options", "Options for the output format and content"
    )

    cve_input_group = input_group.add_mutually_exclusive_group(required=True)

    cve_input_group.add_argument(
        "-cve",
        "--cve_list",
        type=is_valid_file,
        default=None,
        help="Path to the CVE description text file",
    )

    cve_input_group.add_argument(
        "-trivy",
        "--trivy_json",
        type=is_valid_file,
        default=None,
        help="Path of the Trivy JSON file",
    )

    input_group.add_argument(
        "-arc",
        "--architecture_diagram",
        type=argparse.FileType("r"),
        default=None,
        required=False,
        help="Path to the architecture diagram file (image or text)",
    )

    input_group.add_argument(
        "-dep",
        "--dependency_list",
        type=argparse.FileType("r"),
        default=None,
        required=False,
        help="Path to the dependency list text file",
    )

    input_group.add_argument(
        "-api",
        "--api_documentation",
        type=argparse.FileType("r"),
        default=None,
        required=False,
        help="Documentation of a system's API",
    )

    input_group.add_argument(
        "-src",
        "--source_code",
        type=is_valid_directory,
        default=None,
        required=False,
        help="Path to the source code repository folder",
    )

    input_group.add_argument(
        "-s",
        "--state",
        type=str,
        default="state.json",
        required=False,
        help="Path to state file for reducing requests to the LLM API.",
    )

    output_group.add_argument(
        "-llm",
        "--large_language_model",
        type=str,
        choices=["Mistral"],
        default="Mistral",
        help="Large language model option (only option now is Mistral)",
    )

    output_group.add_argument(
        "-o",
        "--output",
        type=str,
        choices=["severity"],
        default="severity",
        help="Output option (only option now is severity)",
    )

    output_group.add_argument(
        "-of",
        "--output_format",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Output format (text or json)",
    )

    output_group.add_argument(
        "-l",
        "--log_level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the logging level",
    )

    args = parser.parse_args()

    return args


def main():
    args = parse_arguments()
    setup_logging(args.log_level)
    result_code = run_security_army_knife(
        # input
        cve_file_path=args.cve_list,
        trivy_file_path=args.trivy_json,
        architecture_diagram=args.architecture_diagram,
        dependency_list=args.dependency_list,
        api_documentation=args.api_documentation,
        source_code=args.source_code,
        state_file_path=args.state,
        # output
        large_language_model=args.large_language_model,
        output_option=args.output,
        output_format=args.output_format,
    )
    return result_code


if __name__ == "__main__":
    exit(main())

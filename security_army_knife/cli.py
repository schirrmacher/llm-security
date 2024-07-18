import os
import json
import time
import logging
import argparse

import pandas as pd
from typing import TextIO

from security_army_knife.mistral_model import MistralModel
from security_army_knife.base_model import BaseModel
from security_army_knife.application_agent import ApplicationAgent
from security_army_knife.cve_categorizer_agent import (
    CVECategorizerAgent,
    CVECategory,
)
from security_army_knife.cve import CVE

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
    cve_description: TextIO,
    architecture_diagram: TextIO,
    dependency_list: TextIO,
    api_documentation: TextIO,
    source_code: str,
    large_language_model: str,
    output_option: str,
    output_format: str,
) -> int:
    logger = logging.getLogger("SecurityArmyKnife")
    try:

        model: BaseModel
        if large_language_model == "Mistral":
            model = MistralModel()
        else:
            raise ValueError(f"{large_language_model} not supported.")

        try:
            advisories = json.loads(cve_description.read())
        except:
            raise ValueError(
                f"The CVEs must be formatted as JSON list with objects containing 'name' and 'description' attributes."
            )

        cves = CVE.from_json_list(advisories)

        categorizer = CVECategorizerAgent(model)
        categorized_cves = categorizer.categorize(cves=cves)

        for c in categorized_cves:
            print(f"{c.name}: {c.category}")

        app_cves = [
            e for e in categorized_cves if e.category == CVECategory.app
        ]
        app_cve_analyzer = ApplicationAgent(model)
        analyzed_app_cves = app_cve_analyzer.categorize(cves=app_cves)

        for cve in analyzed_app_cves:
            print(f"{cve.name}: {cve.category} {cve.code_queries}")

        return 0

    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return 1

    finally:
        cve_description.close()
        architecture_diagram.close()
        dependency_list.close()
        api_documentation.close()


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

    input_group.add_argument(
        "-cve",
        "--cve_description",
        type=argparse.FileType("r"),
        required=True,
        help="Path to the CVE description text file",
    )

    input_group.add_argument(
        "-arc",
        "--architecture_diagram",
        type=argparse.FileType("r"),
        required=True,
        help="Path to the architecture diagram file (image or text)",
    )

    input_group.add_argument(
        "-dep",
        "--dependency_list",
        type=argparse.FileType("r"),
        required=True,
        help="Path to the dependency list text file",
    )

    input_group.add_argument(
        "-api",
        "--api_documentation",
        type=argparse.FileType("r"),
        required=True,
        help="Documentation of a system's API",
    )

    input_group.add_argument(
        "-src",
        "--source_code",
        type=is_valid_directory,
        required=True,
        help="Path to the source code repository folder",
    )

    input_group.add_argument(
        "-s",
        "--state",
        type=is_valid_file,
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

    # Validate the source_code argument to ensure it's a directory
    if not os.path.isdir(args.source_code):
        parser.error(
            f"The source_code path '{args.source_code}' is not a valid directory"
        )

    return args


def main():
    args = parse_arguments()
    setup_logging(args.log_level)
    result_code = run_security_army_knife(
        # input
        cve_description=args.cve_description,
        architecture_diagram=args.architecture_diagram,
        dependency_list=args.dependency_list,
        api_documentation=args.api_documentation,
        source_code=args.source_code,
        state=args.state_file,
        # output
        large_language_model=args.large_language_model,
        output_option=args.output,
        output_format=args.output_format,
    )
    return result_code


if __name__ == "__main__":
    exit(main())

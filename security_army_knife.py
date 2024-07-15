import argparse
import logging
from typing import TextIO, BinaryIO

ASCII_ART = """
░█▀▀░█▀▀░█▀▀░█░█░█▀▄░▀█▀░▀█▀░█░█░░░█▀█░█▀▄░█▄█░█░█░░░█░█░█▀█░▀█▀░█▀▀░█▀▀
░▀▀█░█▀▀░█░░░█░█░█▀▄░░█░░░█░░░█░░░░█▀█░█▀▄░█░█░░█░░░░█▀▄░█░█░░█░░█▀▀░█▀▀
░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░░▀░░░▀░░░░▀░▀░▀░▀░▀░▀░░▀░░░░▀░▀░▀░▀░▀▀▀░▀░░░▀▀▀
"""


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logger = logging.getLogger("SecurityArmyKnife")
    logger.info(ASCII_ART)


def run_security_army_knife(
    cve_description: TextIO,
    architecture_diagram: TextIO,
    dependency_list: TextIO,
    large_language_model: str,
    output_option: str,
    output_format: str,
) -> int:
    logger = logging.getLogger("SecurityArmyKnife")
    try:
        logger.info(f"CVE Description File: {cve_description.name}")
        logger.info(f"Architecture Diagram File: {architecture_diagram.name}")
        logger.info(f"Dependency List File: {dependency_list.name}")
        logger.info(f"Large Language Model Option: {large_language_model}")
        logger.info(f"Output Option: {output_option}")
        logger.info(f"Output Format: {output_format}")

        # You can add the processing logic for each file here

        return 0  # Success code

    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return 1  # Error code

    finally:
        cve_description.close()
        architecture_diagram.close()
        dependency_list.close()


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Analyze CVEs to accelerate decisions."
    )

    parser.add_argument(
        "-cve",
        "--cve_description",
        type=argparse.FileType("r"),
        required=True,
        help="Path to the CVE description text file",
    )

    parser.add_argument(
        "-arc",
        "--architecture_diagram",
        type=argparse.FileType("r"),
        required=True,
        help="Path to the architecture diagram file (image or text)",
    )

    parser.add_argument(
        "-dep",
        "--dependency_list",
        type=argparse.FileType("r"),
        required=True,
        help="Path to the dependency list text file",
    )

    parser.add_argument(
        "-llm",
        "--large_language_model",
        type=str,
        choices=["Mistral"],
        required=True,
        help="Large language model option (only option now is Mistral)",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        choices=["severity"],
        required=True,
        help="Output option (only option now is severity)",
    )

    parser.add_argument(
        "-of",
        "--output_format",
        type=str,
        choices=["text", "json"],
        required=True,
        help="Output format (text or json)",
    )

    args = parser.parse_args()
    return args


def main():
    setup_logging()
    args = parse_arguments()
    result_code = run_security_army_knife(
        cve_description=args.cve_description,
        architecture_diagram=args.architecture_diagram,
        dependency_list=args.dependency_list,
        large_language_model=args.large_language_model,
        output_option=args.output,
        output_format=args.output_format,
    )
    return result_code


if __name__ == "__main__":
    exit(main())

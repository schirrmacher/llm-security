import json
import time
import logging
import argparse

import pandas as pd
from typing import TextIO
from security_army_knife.mistral_agent import MistralAgent
from llama_index.core.llms import ChatMessage

ASCII_ART = """
░█▀▀░█▀▀░█▀▀░█░█░█▀▄░▀█▀░▀█▀░█░█░░░█▀█░█▀▄░█▄█░█░█░░░█░█░█▀█░▀█▀░█▀▀░█▀▀
░▀▀█░█▀▀░█░░░█░█░█▀▄░░█░░░█░░░█░░░░█▀█░█▀▄░█░█░░█░░░░█▀▄░█░█░░█░░█▀▀░█▀▀
░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░░▀░░░▀░░░░▀░▀░▀░▀░▀░▀░░▀░░░░▀░▀░▀░▀░▀▀▀░▀░░░▀▀▀
"""


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
    )
    logger = logging.getLogger("SecurityArmyKnife")
    logger.info(ASCII_ART)


def run_security_army_knife(
    cve_description: TextIO,
    architecture_diagram: TextIO,
    dependency_list: TextIO,
    api_documentation: TextIO,
    large_language_model: str,
    output_option: str,
    output_format: str,
) -> int:
    logger = logging.getLogger("SecurityArmyKnife")
    try:
        if large_language_model == "Mistral":

            mistral = MistralAgent()

            try:
                advisories = json.loads(cve_description.read())
            except:
                raise ValueError(
                    f"The CVEs must be formatted as JSON list with objects containing 'name' and 'description' attributes."
                )

            comparison_results = []

            for advisory in advisories:
                logger.info(f"+++ Analyzing {advisory['name']} +++")

                task = """
                Decide about the severity of the following CVE.
                Add a short explanation about the vulnerability and why you decided to choose the severity."""
                task += f"{advisory['name']}: {advisory['description']}"

                architecture_analysis = """
                Now take the architecture diagram into consideration and adapt the severity.
                """
                architecture_analysis += architecture_diagram.read()

                dependency_analysis = """
                Now take the dependencies into consideration and change adapt the severity.
                """
                dependency_analysis += dependency_list.read()

                context_knowledge = """
                Now consider the following and change adapt the severity:
                The targeted application is a Java microservice deployed in Google Kubernetes Engine (GKE) via a container.
                We assume no local attacks only malicious requests from public internet or from another container.
                We apply Java Eclipse Temurin the open source Java SE build based upon OpenJDK.
                The application does not parse YAML files.
                Availability is of high importance.
                """

                api_analysis = """
                Challenge your analysis by looking at the API spec and adapt the severity.
                We assume the API performs solid sanitization and only accepts described formats and files.
                """
                api_analysis += api_documentation.read()

                messages = [
                    ChatMessage(
                        role="system",
                        content="You are the accurate and professional security analyst.",
                    ),
                    ChatMessage(
                        role="user",
                        content=task,
                    ),
                    # ChatMessage(
                    #     role="user",
                    #     content=architecture_analysis,
                    # ),
                    ChatMessage(
                        role="user",
                        content=context_knowledge,
                    ),
                    ChatMessage(
                        role="user",
                        content=api_analysis,
                    ),
                ]
                response = mistral.talk(messages, json=False)

                formatting = f"Format the CVE analysis as JSON object with name, explanation, urgent (true or false), severity (low, medium, high), explanation: {response.message.content}"
                formatted_response = mistral.talk(
                    [
                        ChatMessage(
                            role="user",
                            content=formatting,
                        ),
                    ],
                    json=True,
                )

                try:
                    llm_analysis = json.loads(
                        formatted_response.message.content
                    )
                except Exception as e:
                    logger.error(
                        f"Issues parsing the Mistral JSON response: {e}"
                    )

                urgency_match = llm_analysis["urgent"] == advisory["urgent"]
                severity_match = (
                    llm_analysis["severity"].lower()
                    == advisory["severity"].lower()
                )

                status = ""
                if urgency_match and severity_match:
                    status = "✅"
                elif urgency_match:
                    status = "🟡"
                else:
                    status = "❌"

                comparison_results.append(
                    {
                        "Passed": status,
                        "CVE": advisory["name"],
                        "Urgency (human/machine)": f"{advisory['urgent']}/{llm_analysis['urgent']}",
                        "Severity (human/machine)": f"{advisory['severity']}/{llm_analysis['severity']}",
                        "Human Explanation": advisory["explanation"],
                        "Machine Explanation": llm_analysis["explanation"],
                    }
                )

                if urgency_match:
                    print(f"> {llm_analysis['name']}, urgent: ✅")
                else:
                    print(
                        f"> {llm_analysis['name']}, urgency match: ❌\n\n- machine: {llm_analysis['explanation']}\n- human: {advisory['explanation']}\n\n"
                    )

        timestamp = int(time.time())
        result_df = pd.DataFrame(comparison_results)
        result_df.to_html(f"{timestamp}-comparison.html", index=False)

        return 0

    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return 1  # Error code

    finally:
        cve_description.close()
        architecture_diagram.close()
        dependency_list.close()
        api_documentation.close()


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
        "-api",
        "--api_documentation",
        type=argparse.FileType("r"),
        required=True,
        help="Documentation of a system's API",
    )

    parser.add_argument(
        "-llm",
        "--large_language_model",
        type=str,
        choices=["Mistral"],
        default="Mistral",
        help="Large language model option (only option now is Mistral)",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        choices=["severity"],
        default="severity",
        help="Output option (only option now is severity)",
    )

    parser.add_argument(
        "-of",
        "--output_format",
        type=str,
        choices=["text", "json"],
        default="text",
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
        api_documentation=args.api_documentation,
        large_language_model=args.large_language_model,
        output_option=args.output,
        output_format=args.output_format,
    )
    return result_code


if __name__ == "__main__":
    exit(main())

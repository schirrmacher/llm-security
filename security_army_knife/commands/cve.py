import json
import logging
import argparse
from typing import TextIO, Optional, List

from security_army_knife.commands.util import (
    is_valid_directory,
    is_valid_file,
    get_model,
)
from security_army_knife.ui.spinner import Spinner
from security_army_knife.agents.source_code_agent import SourceCodeAgent
from security_army_knife.agents.api_spec_agent import APISpecAgent
from security_army_knife.agents.cve_categorizer import (
    CVECategorizerAgent,
)
from security_army_knife.analysis.cve_analysis import CVE, CVEAnalysis
from security_army_knife.agents.agent_tree import AgentTree
from security_army_knife.agents.base_agent import BaseAgent, AgentEvent as Event
from security_army_knife.files.trivy_importer import TrivyImporter
from security_army_knife.agents.architecuture_agent import ArchitectureAgent
from security_army_knife.agents.evaluation_agnet import EvaluationAgent
from security_army_knife.agents.infrastructure_agent import InfrastructureAgent


def add_subcommand(subparsers):

    parser = subparsers.add_parser(
        "cve", help="Analyze CVEs to accelerate decisions."
    )
    parser.set_defaults(which="cve")

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
        "-inf",
        "--infra",
        type=argparse.FileType("r"),
        default=None,
        required=False,
        help="Path to the infra as code file",
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
        choices=["mistral", "gemini"],
        default="mistral",
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
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format (text or json or markdown)",
    )

    output_group.add_argument(
        "-l",
        "--log_level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the logging level",
    )
    output_group.add_argument(
        "-f",
        "--output_filename",
        type=str,
        default="cve_analysis",
        required=False,
        help="Filename for the output (without extension).",
    )


def run_cve_analysis(
    cve_file_path: Optional[str],
    trivy_file_path: Optional[str],
    architecture_diagram: Optional[TextIO],
    dependency_list: Optional[TextIO],
    api_documentation: Optional[TextIO],
    source_code: Optional[str],
    infrastructure_code: Optional[TextIO],
    state_file_path: Optional[str],
    large_language_model: str,
    output_option: str,
    output_format: str,
    output_filename: Optional[str] = "analysis_result",
) -> int:
    logger = logging.getLogger("SecurityArmyKnife")
    spinner = Spinner()

    model = get_model(large_language_model)

    try:
        if trivy_file_path:
            with open(trivy_file_path, "r") as file:
                advisories = file.read()
                cve_list = TrivyImporter(trivy_file_path).get_cves()
        elif cve_file_path:
            with open(cve_file_path, "r") as file:
                advisories = json.loads(file.read())
                cve_list = CVE.from_json_list(advisories)

    except Exception as e:
        raise ValueError(f"There are issues with parsing CVEs from: {e}")

    if state_file_path:
        cve_analysis = CVEAnalysis.load_and_merge_state(
            file_path=state_file_path, new_cves=cve_list
        )

    agents = [CVECategorizerAgent(model)]

    if infrastructure_code:
        agents.append(
            InfrastructureAgent(
                model=model, infrastructure_code=infrastructure_code
            )
        )

    if source_code:
        agents.append(SourceCodeAgent(model, source_code_path=source_code))

    if api_documentation:
        agents.append(APISpecAgent(model, api_spec=api_documentation))

    if architecture_diagram:
        agents.append(
            ArchitectureAgent(model, architecture_diagram=architecture_diagram)
        )
        agents.append(EvaluationAgent(model))

    def handle_event(event: Event):
        if event.event_type == Event.Type.BEFORE_ANALYSIS:
            if hasattr(event, "cve") and event.cve:
                logger.info(f"· {event.cve.name}")
            else:
                logger.info(f"· {event.message}")
            spinner.start()
        elif event.event_type == Event.Type.REQUEST:
            spinner.stop()
            spinner.set_http_request_spinner()
            spinner.start()
        elif event.event_type == Event.Type.RESPONSE:
            spinner.stop()
            spinner.set_default_spinner()
            spinner.start()
        elif event.event_type == Event.Type.AFTER_ANALYSIS:
            spinner.stop()
            cve_analysis.save_to_file(file_path=state_file_path)
        elif event.event_type == Event.Type.INFORMATION:
            spinner.stop()
            logger.info(f"  - {str(event.message)}")
        elif event.event_type == Event.Type.ERROR:
            spinner.stop()
            logger.info(f"  - error: {event.message}")
        else:
            spinner.stop()
            logger.info(f"  - {str(event.event_type.name)}")

    def handle_agent(agent: BaseAgent, analysis: CVEAnalysis):
        logger.info(f"\n{agent.__class__.__name__}\n")
        analysis = agent.analyze(
            analysis=analysis,
            handle_event=handle_event,
        )
        return analysis

    try:
        tree = AgentTree(agents=agents)
        tree.traverse(handle_agent, target=cve_analysis)

        if output_format in ["markdown", "both"]:
            with open(f"{output_filename}.md", "w") as file:
                for cve in cve_list:
                    file.write(cve.to_markdown())
            logger.info(
                f"Markdown file {output_filename}.md created successfully"
            )

    except KeyboardInterrupt:
        spinner.stop()
        logger.info("👋")
        return 0

    return 0

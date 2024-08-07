import json
import logging
import argparse

from typing import TextIO, Optional

from security_army_knife.commands.util import (
    get_model,
)
from security_army_knife.ui.spinner import Spinner
from security_army_knife.agents.sdr_arch_agent import SDRArchAgent
from security_army_knife.agents.sdr_threat_agent import SDRThreatAgent
from security_army_knife.agents.base_agent import AgentEvent as Event
from security_army_knife.analysis.sdr import SDR
from security_army_knife.agents.agent_tree import AgentTree
from security_army_knife.agents.base_agent import BaseAgent


def add_subcommand(subparsers):

    parser = subparsers.add_parser(
        "sdr", help="Utils for Security Design Reviews."
    )
    parser.set_defaults(which="sdr")

    input_group = parser.add_argument_group(
        "input files", "Input files required for analysis"
    )
    output_group = parser.add_argument_group(
        "output options", "Options for the output format and content"
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
        "-api",
        "--api_documentation",
        type=argparse.FileType("r"),
        default=None,
        required=False,
        help="Documentation of a system's API",
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
        "-of",
        "--output_format",
        type=str,
        choices=["markdown"],
        default="markdown",
        help="Output format",
    )

    output_group.add_argument(
        "-f",
        "--output_filename",
        type=str,
        default="sdr",
        help="Filename of the analysis result",
    )

    output_group.add_argument(
        "-l",
        "--log_level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the logging level",
    )


def run_sdr_analysis(
    architecture_diagram: Optional[TextIO],
    api_documentation: Optional[TextIO],
    large_language_model: str,
    output_format: str,
    output_filename: str,
) -> int:
    logger = logging.getLogger("SecurityArmyKnife")
    spinner = Spinner()

    model = get_model(large_language_model)

    tree = AgentTree(
        [
            SDRArchAgent(
                model=model,
                architecture_diagram=architecture_diagram,
            ),
            SDRThreatAgent(
                model=model,
                api_documentation=api_documentation,
                architecture_diagram=architecture_diagram,
            ),
        ]
    )

    try:

        sdr = SDR()

        def handle_event(event: Event):
            if event.event_type == Event.Type.REQUEST:
                spinner.start()
            elif event.event_type == Event.Type.RESPONSE:
                spinner.stop()
            elif event.event_type == Event.Type.INFORMATION:
                spinner.stop()
                logger.info(f"  - {str(event.message)}")
            elif event.event_type == Event.Type.ERROR:
                spinner.stop()
                logger.error(f"  - error: {event.message}")
            else:
                logger.info(f"  - {event.message}")

        def handle_agent(agent: BaseAgent, sdr: SDR):
            logger.info(f"\n{agent.__class__.__name__}\n")
            sdr = agent.analyze(
                handle_event=handle_event,
                target=sdr,
            )
            return sdr

        tree.traverse(handle_agent, target=sdr)

        with open(f"{output_filename}.md", "w") as file:
            file.write(sdr.to_markdown())

    except KeyboardInterrupt:
        logger.info("👋")
        return 0

    finally:
        spinner.stop()

    return 0

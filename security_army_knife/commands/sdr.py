import logging
import argparse
import textwrap

from typing import TextIO, Optional

from security_army_knife.commands.util import (
    get_model,
)
from security_army_knife.ui.spinner import Spinner
from security_army_knife.agents.sdr_agent import SDRAgent
from security_army_knife.agents.base_agent import AgentEvent as Event


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
        choices=["yaml"],
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


def run_sdr_analysis(
    architecture_diagram: Optional[TextIO],
    api_documentation: Optional[TextIO],
    large_language_model: str,
    output_format: str,
) -> int:
    logger = logging.getLogger("SecurityArmyKnife")
    spinner = Spinner()

    model = get_model(large_language_model)

    sdr_agent = SDRAgent(model=model)

    try:

        def handle_event(event: Event):
            if event.event_type == Event.Type.REQUEST:
                spinner.start()
            elif event.event_type == Event.Type.RESPONSE:
                spinner.stop()

        response = sdr_agent.analyze(
            handle_event=handle_event,
            api_documentation=api_documentation,
            architecture_diagram=architecture_diagram,
        )
        print(response)
    except KeyboardInterrupt:
        spinner.stop()
        logger.info("👋")
        return 0

    return 0

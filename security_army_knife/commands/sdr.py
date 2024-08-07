import json
import logging
import argparse

from typing import TextIO, Optional

from security_army_knife.commands.util import (
    get_model,
)
from security_army_knife.ui.spinner import Spinner
from security_army_knife.agents.sdr_agent import SDRAgent
from security_army_knife.agents.threat_agent import ThreatAgent
from security_army_knife.agents.base_agent import AgentEvent as Event
from security_army_knife.analysis.sdr import SDR


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
    threat_agent = ThreatAgent(model=model)

    try:

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

        sdr = sdr_agent.analyze(
            handle_event=handle_event,
            api_documentation=api_documentation,
            architecture_diagram=architecture_diagram,
        )

        print(sdr.to_yaml())

        threats = threat_agent.analyze(
            handle_event=handle_event,
            api_documentation=api_documentation,
            architecture_diagram=architecture_diagram,
            security_design_review=sdr,
        )

        print(threats)

    except KeyboardInterrupt:
        logger.info("👋")
        return 0

    finally:
        spinner.stop()

    return 0

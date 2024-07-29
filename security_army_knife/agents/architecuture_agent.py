import logging
import json
from typing import Callable, Type, TextIO, Optional

from llama_index.core.llms import ChatMessage
from security_army_knife.agents.base_agent import (
    BaseAgent,
    AgentEvent as Event,
    InformationEvent,
    CachedEvent,
    BeforeAnalysis,
    AfterAnalysis,
    ErrorEvent,
)
from security_army_knife.base_model import BaseModel
from security_army_knife.agents.cve_categorizer import CVECategorizerAgent
from security_army_knife.analysis.cve import CVE
from security_army_knife.analysis.architecture_analysis import (
    ArchitectureAnalysis,
)
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET


class ArchitectureAgent(BaseAgent):

    dependencies: list[Type] = [CVECategorizerAgent]

    def __init__(
        self,
        model: BaseModel,
        architecture_diagram: Optional[TextIO] = None,
    ):
        super().__init__(model=model)
        self.logger = logging.getLogger("SecurityArmyKnife")
        self.architecture_diagram_content = (
            self._parse_architecture_diagram(architecture_diagram)
            if architecture_diagram
            else None
        )

    def _parse_architecture_diagram(self, architecture_diagram: TextIO) -> str:
        content = architecture_diagram.read()
        if architecture_diagram.name.endswith(".html"):
            return self._parse_html(content)
        elif architecture_diagram.name.endswith(".xml"):
            return self._parse_xml(content)
        else:
            return content  # D2 format

    def _parse_html(self, content: str) -> str:
        soup = BeautifulSoup(content, "html.parser")
        return soup.get_text()

    def _parse_xml(self, content: str) -> str:
        root = ET.fromstring(content)
        return ET.tostring(root, encoding="unicode")

    def analyze(
        self, cve_list: list[CVE], handle_event: Callable[[Event], None]
    ) -> list[CVE]:
        for cve in cve_list:
            self.logger.info(f"Analyzing {cve.name} in ArchitectureAgent...")
            handle_event(BeforeAnalysis(cve))

            if cve.architecture_analysis:
                handle_event(CachedEvent(cve))
                continue

            task = (
                f"For the following CVE, what infrastructure conditions must be met for the vulnerability to be exploitable? "
                f"Consider architecture diagram and factors such as network configuration, software versions, dependencies.{cve.to_json()}"
            )
            formatting = (
                "Format the result as JSON and include the attribute 'infrastructure_conditions' as a string list. "
                "Ensure each condition is specific and actionable."
            )

            context = {
                "architecture_diagram": self.architecture_diagram_content,
            }

            messages = [
                ChatMessage(
                    role="system",
                    content="You are an architectural security expert.",
                ),
                ChatMessage(
                    role="user",
                    content=json.dumps({"task": task, "context": context}),
                ),
                ChatMessage(
                    role="user",
                    content=formatting,
                ),
            ]

            try:
                response = self.model.talk(messages, json=True)
                self.logger.info(f"Received response for {cve.name}")
                json_object = json.loads(response.message.content)

                infrastructure_conditions = json_object.get(
                    "infrastructure_conditions", []
                )
                cve.architecture_analysis = ArchitectureAnalysis(
                    infrastructure_conditions=infrastructure_conditions
                )
                handle_event(
                    InformationEvent(
                        cve,
                        f"infrastructure_conditions: {infrastructure_conditions}",
                    )
                )

                self.logger.info(
                    f"Architecture Analysis:\n{cve.architecture_analysis}"
                )
            except Exception as e:
                self.logger.error(f"Unexpected error for {cve.name}: {e}")
                handle_event(ErrorEvent(cve, error=e))

            handle_event(AfterAnalysis(cve))

        return cve_list

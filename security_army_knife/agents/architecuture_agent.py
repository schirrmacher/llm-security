import logging
import json
from typing import Callable, Type, TextIO, Optional

from llama_index.core.llms import ChatMessage
from security_army_knife.agents.base_agent import (
    AgentEvent as Event,
    InformationEvent,
    CachedEvent,
    BeforeAnalysis,
    AfterAnalysis,
    ErrorEvent,
    RequestEvent,
    ResponseEvent,
)
from security_army_knife.models.base_model import BaseModel
from security_army_knife.agents.base_cve_agent import BaseCVEAgent
from security_army_knife.agents.cve_categorizer import CVECategorizerAgent
from security_army_knife.analysis.cve import CVE
from security_army_knife.analysis.architecture_analysis import (
    ArchitectureAnalysis,
)
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET


class ArchitectureAgent(BaseCVEAgent):

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
                handle_event(RequestEvent(cve))
                response = self.model.talk(messages, json=True)
                handle_event(ResponseEvent(cve, response.message.content))

                json_object = json.loads(response.message.content)

                infrastructure_conditions = json_object.get(
                    "infrastructure_conditions", []
                )
                cve.architecture_analysis = ArchitectureAnalysis(
                    infrastructure_conditions=infrastructure_conditions
                )
                message = f"conditions: {len(infrastructure_conditions)}"
                handle_event(InformationEvent(cve, message))

            except Exception as e:
                handle_event(ErrorEvent(cve, error=e))

            handle_event(AfterAnalysis(cve))

        return cve_list

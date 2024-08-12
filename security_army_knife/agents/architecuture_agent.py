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
                f"# Introduction\n"
                f"- You are an architectural security expert specializing in evaluating software vulnerabilities based on architectural diagrams and system configurations.\n"
                f"- Your task is to identify infrastructure conditions that could facilitate or hinder the exploitation of a given CVE.\n"
                f"- Base your evaluation on the architecture diagram provided, as well as network configurations, software versions, dependencies, and other relevant architectural details.\n\n"
                f"# Tasks\n"
                f"- Complete the following tasks without repeating this description in your response.\n\n"
                f"## Analyze CVE Details\n"
                f"- Consider the CVE's name, description, and category to understand its potential impact.\n"
                f"- Evaluate how the vulnerability could affect the system's confidentiality, integrity, and availability.\n\n"
                f"## Evaluate Architecture Diagram\n"
                f"- Analyze the architecture diagram to identify key components such as servers, network segments, and software dependencies.\n"
                f"- Determine how these components might interact with each other in the context of the CVE.\n"
                f"- Pay attention to the layout and structure of the system to identify potential weak points.\n\n"
                f"## Identify Infrastructure Conditions\n"
                f"- List infrastructure conditions that must be met for the CVE to be exploitable.\n"
                f"- Consider factors such as network segmentation, firewall policies, and access controls.\n"
                f"- Include conditions related to software versions, dependencies, and system configurations.\n\n"
                f"## Environment Considerations\n"
                f"- Assess how environmental factors like network topology and hardware configurations could affect exploitability.\n"
                f"- Consider whether the current environment provides sufficient protection against the CVE.\n"
                f"- Identify any additional architectural changes that could mitigate the risk.\n\n"
                f"## Summary\n"
                f"- Create a JSON object summarizing your findings with the following attributes:\n"
                f"{{\n"
                f'"infrastructure_conditions": [\n'
                f'"Condition 1: Description...",\n'
                f'"Condition 2: Description..."\n'
                f"]\n"
                f"}}\n\n"
                f"## Final Notes\n"
                f"- Ensure your analysis clearly communicates the risk to stakeholders with varying technical expertise.\n"
                f"- Focus on actionable insights and recommendations to guide decision-making.\n"
                f"- Maintain a concise yet comprehensive explanation of your evaluation process.\n\n"
                f"# CVE Data for Analysis\n"
                f"- Name: {cve.name}\n"
                f"- Description: {cve.description}\n"
                f"- Category: {cve.category}\n"
                f"- Architecture Diagram: {self.architecture_diagram_content if self.architecture_diagram_content else 'No architecture diagram provided'}\n"
            )

            messages = [
                ChatMessage(
                    role="system",
                    content="You are an architectural security expert.",
                ),
                ChatMessage(
                    role="user",
                    content=task,
                ),
            ]

            try:
                handle_event(RequestEvent(cve=cve))
                response = self.model.talk(messages, json=True)
                json_start_index = response.message.content.find("{")
                json_end_index = response.message.content.rfind("}") + 1

                if json_start_index != -1 and json_end_index != -1:
                    json_object = json.loads(
                        response.message.content[
                            json_start_index:json_end_index
                        ]
                    )

                    infrastructure_conditions = json_object.get(
                        "infrastructure_conditions", []
                    )
                    cve.architecture_analysis = ArchitectureAnalysis(
                        infrastructure_conditions=infrastructure_conditions
                    )
                    message = f"conditions: {len(infrastructure_conditions)}"
                    handle_event(InformationEvent(cve=cve, message=message))
                else:
                    raise ValueError("No JSON object found in response")

            except (json.JSONDecodeError, ValueError) as e:
                self.logger.error(f"Failed to parse JSON: {e}")
                handle_event(ErrorEvent(cve=cve, error=e))
            except Exception as e:
                handle_event(ErrorEvent(cve=cve, error=e))

            handle_event(AfterAnalysis(cve))

        return cve_list

import json
from typing import Callable, Type, TextIO

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
from security_army_knife.analysis.cve_analysis import CVEAnalysis
from security_army_knife.models.base_model import BaseModel
from security_army_knife.agents.base_cve_agent import BaseCVEAgent
from security_army_knife.agents.cve_categorizer import CVECategorizerAgent
from security_army_knife.analysis.cve_analysis import CVE
from security_army_knife.analysis.api_spec_analysis import APISpecAnalysis


class APISpecAgent(BaseCVEAgent):

    dependencies: list[Type] = [CVECategorizerAgent]

    def __init__(self, model: BaseModel, api_spec: TextIO):
        super().__init__(model=model)
        self.api_spec: TextIO = api_spec

    def analyze(
        self,
        analysis: CVEAnalysis,
        handle_event: Callable[[Event], None],
    ) -> CVEAnalysis:

        api_spec = self.api_spec.read()

        for cve in analysis.cves:

            handle_event(BeforeAnalysis(cve))

            if cve.api_spec_analysis:
                handle_event(CachedEvent(cve))
                continue

            task = (
                f"# Introduction\n"
                f"- You are an API security expert tasked with analyzing API specifications in the context of specific CVEs.\n"
                f"- Your goal is to evaluate whether the provided API specification facilitates or mitigates the exploitation of a given CVE.\n\n"
                f"# Tasks\n"
                f"- Complete the following tasks without repeating this description in your response.\n\n"
                f"## Analyze CVE Details\n"
                f"- Review the CVE details, including its name, description, and category.\n"
                f"- Determine the potential impact on confidentiality, integrity, and availability (CIA triad).\n\n"
                f"## Evaluate API Specification\n"
                f"- Examine the provided API specification to identify any vulnerabilities or security flaws.\n"
                f"- Assess whether the API specification could facilitate the exploitation of the CVE.\n"
                f"- Consider aspects such as input validation, authentication, authorization, and error handling in the API.\n\n"
                f"## Risk Assessment\n"
                f"- Determine whether the API specification increases the risk associated with the CVE.\n"
                f"- Identify specific elements in the API that contribute to or mitigate the risk.\n\n"
                f"## Summary\n"
                f"- Provide a JSON object summarizing your findings with the following attributes:\n"
                f"{{\n"
                f'  "facilitates_attack": true|false,\n'
                f'  "explanation": "A detailed explanation of why the API specification does or does not facilitate the exploitation of the CVE."\n'
                f"}}\n\n"
                f"# CVE Data for Analysis\n"
                f"- Name: {cve.name}\n"
                f"- Description: {cve.description}\n"
                f"- Category: {cve.category}\n"
                f"- API Specification: {api_spec}\n"
            )

            messages = [
                ChatMessage(
                    role="system",
                    content="You are an API designer.",
                ),
                ChatMessage(
                    role="user",
                    content=task,
                ),
            ]

            try:
                handle_event(RequestEvent(cve=cve))
                response = self.model.talk(messages, json=True)
                json_object = json.loads(response.message.content)
                cve.api_spec_analysis = APISpecAnalysis.from_json(json_object)
                handle_event(
                    InformationEvent(
                        cve=cve,
                        message=f"facilitates_attack: {cve.api_spec_analysis.facilitates_attack}",
                    )
                )

            except Exception as e:
                cve.api_spec_analysis = None
                handle_event(ErrorEvent(cve=cve, error=e))

            handle_event(AfterAnalysis(cve))

        return analysis

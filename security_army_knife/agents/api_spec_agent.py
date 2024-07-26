import json

from typing import Callable, Type, TextIO

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
from security_army_knife.analysis.api_spec_analysis import APISpecAnalysis


class APISpecAgent(BaseAgent):

    dependencies: list[Type] = [CVECategorizerAgent]

    def __init__(self, model: BaseModel, api_spec: TextIO):
        super().__init__(model=model)
        self.api_spec: TextIO = api_spec

    def analyze(
        self,
        cve_list: list[CVE],
        handle_event: Callable[[Event], None],
    ) -> list[CVE]:

        for cve in cve_list:

            handle_event(BeforeAnalysis(cve))

            if cve.api_spec_analysis:
                handle_event(CachedEvent(cve))
                continue

            task = f"""What messages or files are affected by this vulnerability? {cve.name}: {cve.description}"""
            api_task = f"Is the following API definition listing a way to exploit this?: {self.api_spec.read()}"
            formatting = """
            Format the result as a single JSON object, like: {
                "critical": true|false,
                "explanation": "Why is this critical or not critical?"
            }
            """

            messages = [
                ChatMessage(
                    role="system",
                    content="You are an API designer.",
                ),
                ChatMessage(
                    role="user",
                    content=task,
                ),
                ChatMessage(
                    role="user",
                    content=api_task + formatting,
                ),
            ]

            try:
                response = self.model.talk(messages, json=True)
                json_object = json.loads(response.message.content)
                cve.api_spec_analysis = APISpecAnalysis.from_json(json_object)
                handle_event(
                    InformationEvent(
                        cve,
                        message=f"critical: {cve.api_spec_analysis.critical}",
                    )
                )

            except Exception as e:
                cve.api_spec_analysis = None
                handle_event(ErrorEvent(cve, error=e))

            handle_event(AfterAnalysis(cve))

        return cve_list

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
from security_army_knife.models.base_model import BaseModel
from security_army_knife.agents.base_cve_agent import BaseCVEAgent
from security_army_knife.agents.cve_categorizer import CVECategorizerAgent
from security_army_knife.analysis.cve import CVE
from security_army_knife.analysis.api_spec_analysis import APISpecAnalysis


class APISpecAgent(BaseCVEAgent):

    dependencies: list[Type] = [CVECategorizerAgent]

    def __init__(self, model: BaseModel, api_spec: TextIO):
        super().__init__(model=model)
        self.api_spec: TextIO = api_spec

    def analyze(
        self,
        cve_list: list[CVE],
        handle_event: Callable[[Event], None],
    ) -> list[CVE]:

        api_spec = self.api_spec.read()

        for cve in cve_list:

            handle_event(BeforeAnalysis(cve))

            if cve.api_spec_analysis:
                handle_event(CachedEvent(cve))
                continue

            task = f"""How looks a vulnerable API spec facilitating the following CVE? {cve.name}: {cve.description}"""
            api_task = f"Is the following API spec facilitating the exploit or not?: {api_spec}"
            formatting = """
            Format the result as a single JSON object, like: {
                "facilitates_attack": true|false,
                "explanation": "Why is the API facilitating the vulnerability or not?"
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
                    content=api_task,
                ),
                ChatMessage(
                    role="user",
                    content=formatting,
                ),
            ]

            try:
                handle_event(RequestEvent(cve=cve))
                response = self.model.talk(messages, json=True)
                handle_event(
                    ResponseEvent(cve=cve, message=response.message.content)
                )

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

        return cve_list

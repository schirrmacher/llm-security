import json

from typing import Callable, Type

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

from security_army_knife.agents.base_cve_agent import BaseCVEAgent

from security_army_knife.analysis.cve_analysis import CVECategory, CVEAnalysis


class CVECategorizerAgent(BaseCVEAgent):

    dependencies: list[Type] = []

    def __init__(self, model):
        super(CVECategorizerAgent, self).__init__(model=model)

    def analyze(
        self,
        analysis: CVEAnalysis,
        handle_event: Callable[[Event], None],
    ) -> CVEAnalysis:

        for cve in analysis.cves:

            handle_event(BeforeAnalysis(cve))

            if cve.category != CVECategory.unknown:
                handle_event(CachedEvent(cve))
                continue

            task = f"For the following CVE, choose one of the categories: operating system kernel, operating system distribution library, application layer.{cve.to_dict()}"
            formatting = "Format the result as JSON and add the attribute 'category' with one of: os, distro, app."

            messages = [
                ChatMessage(
                    role="system",
                    content="You are a system and security expert.",
                ),
                ChatMessage(
                    role="user",
                    content=task,
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
                cve.category = json_object.get("category", CVECategory.unknown)

                handle_event(
                    InformationEvent(
                        cve=cve, message=f"categorized => {cve.category}"
                    )
                )

            except Exception as e:
                cve.category = CVECategory.unknown
                handle_event(ErrorEvent(cve=cve, error=e))

            handle_event(AfterAnalysis(cve))

        return analysis

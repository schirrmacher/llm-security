import json
import logging

from llama_index.core.llms import ChatMessage
from security_army_knife.agents.base_agent import BaseAgent

from security_army_knife.analysis.cve import CVE, CVECategory


class CVECategorizerAgent(BaseAgent):

    dependencies = []

    def __init__(self, model):
        super().__init__(model=model)
        self.logger = logging.getLogger("SecurityArmyKnife")

    def analyze(self, cve_list: list[CVE]) -> list[CVE]:

        categorized_cves: list[CVE] = []
        for cve in cve_list:

            task = f"For the following CVE, choose one of the categories: operating system kernel, operating system distribution library, application layer.{cve.to_json()}"
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
                response = self.model.talk(messages, json=True)
                json_object = json.loads(response.message.content)
                cve_categorized = CVE.from_json(json_object)
                categorized_cves.append(cve_categorized)
            except:
                self.logger.error(
                    f"Response for {cve.name} could not be parsed."
                )
                cve.category = CVECategory.unknown
                categorized_cves.append(cve)
        return categorized_cves

import json
import logging

from llama_index.core.llms import ChatMessage
from security_army_knife.agents.base_agent import BaseAgent

from security_army_knife.cve import CVE


class ApplicationAgent(BaseAgent):

    def __init__(self, model):
        super().__init__(model=model)
        self.logger = logging.getLogger("SecurityArmyKnife")

    def categorize(self, cves: list[CVE]) -> list[CVE]:

        categorized_cves: list[CVE] = []
        for cve in cves:

            task = f"For the following CVE, how can you detect it in code? Create a recursive full grep query, only if applicable: {cve.to_json()}"
            formatting = "Format the result as JSON and add the attribute 'code_queries' as a string list to this object. Leave the list empty if not applicable."

            messages = [
                ChatMessage(
                    role="system",
                    content="You are security code reviewer.",
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
                self.logger.debug(response.message.content)
                json_object = json.loads(response.message.content)
                cve_categorized = CVE.from_categorized_cve(
                    cve, json_object["code_queries"]
                )
                categorized_cves.append(cve_categorized)
            except Exception as e:
                self.logger.error(
                    f"Response for {cve.name} could not be parsed: {e}"
                )
                categorized_cves.append(
                    CVE.from_categorized_cve(
                        categorized_cve=cve, code_queries=[]
                    )
                )
        return categorized_cves

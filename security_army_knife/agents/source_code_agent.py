import json
import logging

from llama_index.core.llms import ChatMessage
from security_army_knife.agents.base_agent import BaseAgent

from security_army_knife.analysis.cve import CVE
from security_army_knife.analysis.code_analysis import CodeAnalysis


class ApplicationAgent(BaseAgent):

    dependencies = ["CVECategorizerAgent"]

    def __init__(self, model):
        super().__init__(model=model)
        self.logger = logging.getLogger("SecurityArmyKnife")

    def analyze(self, cve_list: list[CVE]) -> list[CVE]:

        for cve in cve_list:

            if cve.code_analysis:
                logging.info(
                    f"{self.__class__.__name__}: {cve.name}, already analyzed"
                )
                continue

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
                cve.code_analysis = CodeAnalysis(
                    queries=json_object["code_queries"]
                )

            except Exception as e:
                self.logger.error(
                    f"Response for {cve.name} could not be parsed: {e}"
                )
                cve.code_analysis.queries = []
        return cve_list

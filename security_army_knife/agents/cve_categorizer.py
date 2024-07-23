import json
import logging

from typing import Callable

from llama_index.core.llms import ChatMessage
from security_army_knife.agents.base_agent import BaseAgent

from security_army_knife.analysis.cve import CVE, CVECategory


class CVECategorizerAgent(BaseAgent):

    dependencies = []

    def __init__(self, model):
        super().__init__(model=model)
        self.logger = logging.getLogger("SecurityArmyKnife")

    def analyze(
        self,
        cve_list: list[CVE],
        before_cve_analyzed: Callable[[CVE], None],
        after_cve_analyzed: Callable[[CVE], None],
        when_cve_skipped: Callable[[CVE], None],
    ) -> list[CVE]:

        for cve in cve_list:

            before_cve_analyzed(cve)

            if cve.category != CVECategory.unknown:
                when_cve_skipped(cve)
                continue

            logging.info(f"{self.__class__.__name__}: analyzing {cve.name}")

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
                cve.category = json_object.get("category", CVECategory.unknown)

            except:
                self.logger.error(
                    f"Response for {cve.name} could not be parsed."
                )
                cve.category = CVECategory.unknown
                when_cve_skipped(cve)

            after_cve_analyzed(cve)

        return cve_list

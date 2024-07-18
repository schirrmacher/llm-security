import json
import logging

from llama_index.core.llms import ChatMessage
from security_army_knife.base_agent import BaseAgent

from security_army_knife.cve_categorizer_agent import (
    CategorizedCVE,
    CVECategory,
)


class ApplicationCVE(CategorizedCVE):
    def __init__(
        self,
        name: str,
        description: str,
        urgent: bool,
        category: str,
        code_queries: list,
    ):
        super().__init__(name, description, urgent, category=CVECategory.app)
        self.code_queries = code_queries

    @classmethod
    def from_json(cls, json_dict: dict):
        return cls(
            name=json_dict.get("name"),
            description=json_dict.get("description"),
            urgent=json_dict.get("urgent", False),
            category=json_dict.get("category", CVECategory.app),
            code_queries=json_dict.get("code_queries", []),
        )

    @classmethod
    def from_categorized_cve(
        cls, categorized_cve: CategorizedCVE, code_queries: list
    ):
        return cls(
            name=categorized_cve.name,
            description=categorized_cve.description,
            urgent=categorized_cve.urgent,
            code_queries=code_queries,
        )

    def to_json(self):
        cve_json = super().to_json()
        cve_json["code_queries"] = self.code_queries
        return cve_json

    def __str__(self):
        urgency = "Urgent" if self.urgent else "Not Urgent"
        return (
            f"CVE Name: {self.name}\nDescription: {self.description}\n"
            f"Urgency: {urgency}\nCategory: {self.category}\nCode Queries: {self.code_queries}"
        )


class ApplicationAgent(BaseAgent):

    def __init__(self, model):
        super().__init__(model=model)
        self.logger = logging.getLogger("SecurityArmyKnife")

    def categorize(self, cves: list[CategorizedCVE]) -> list[ApplicationCVE]:

        categorized_cves: list[ApplicationCVE] = []
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
                cve_categorized = ApplicationCVE.from_categorized_cve(
                    cve, json_object["code_queries"]
                )
                categorized_cves.append(cve_categorized)
            except Exception as e:
                self.logger.error(
                    f"Response for {cve.name} could not be parsed: {e}"
                )
                categorized_cves.append(
                    ApplicationCVE.from_categorized_cve(
                        categorized_cve=cve, code_queries=[]
                    )
                )
        return categorized_cves

import json
import logging

from llama_index.core.llms import ChatMessage
from security_army_knife.base_agent import BaseAgent

from security_army_knife.cve import CVE


class CVECategory:
    os = "os"
    distro = "distro"
    app = "app"
    unknown = "unknown"


class CategorizedCVE(CVE):
    def __init__(
        self, name: str, description: str, urgent: bool, category: str
    ):
        super().__init__(name, description, urgent)
        self.category = category

    @classmethod
    def from_json(cls, json_dict: dict):
        return cls(
            name=json_dict.get("name"),
            description=json_dict.get("description"),
            urgent=json_dict.get("urgent", False),
            category=json_dict.get("category", CVECategory.unknown),
        )

    def to_json(self):
        cve_json = super().to_json()
        cve_json["category"] = self.category
        return cve_json

    @classmethod
    def from_cve(cls, cve: CVE, category: str):
        return cls(
            name=cve.name,
            description=cve.description,
            urgent=cve.urgent,
            category=category,
        )

    def __str__(self):
        urgency = "Urgent" if self.urgent else "Not Urgent"
        return (
            f"CVE Name: {self.name}\nDescription: {self.description}\n"
            f"Urgency: {urgency}\nCategory: {self.category}"
        )


class CVECategorizerAgent(BaseAgent):

    def __init__(self, model):
        super().__init__(model=model)
        self.logger = logging.getLogger("SecurityArmyKnife")

    def categorize(self, cves: list[CVE]) -> list[CategorizedCVE]:

        categorized_cves: list[CategorizedCVE] = []
        for cve in cves:

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
                cve_categorized = CategorizedCVE.from_json(json_object)
                categorized_cves.append(cve_categorized)
            except:
                self.logger.error(
                    f"Response for {cve.name} could not be parsed."
                )
                categorized_cves.append(
                    CategorizedCVE.from_cve(
                        cve=cve, category=CVECategory.unknown
                    )
                )
        return categorized_cves

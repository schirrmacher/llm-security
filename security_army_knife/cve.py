import json


class CVE:
    def __init__(self, name: str, description: str, urgent: bool):
        self.name = name
        self.description = description
        self.urgent = urgent

    @classmethod
    def from_json(cls, json_dict: dict):
        return cls(
            name=json_dict.get("name"),
            description=json_dict.get("description"),
            urgent=json_dict.get(
                "urgent", False
            ),  # Default to False if not provided
        )

    @classmethod
    def from_json_list(cls, json_list: list):
        return [cls.from_json(item) for item in json_list]

    def to_json(self):
        return {
            "name": self.name,
            "description": self.description,
            "urgent": self.urgent,
        }

    def __str__(self):
        urgency = "Urgent" if self.urgent else "Not Urgent"
        return f"CVE Name: {self.name}\nDescription: {self.description}\nUrgency: {urgency}"

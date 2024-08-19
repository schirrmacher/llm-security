import json
from typing import Optional


class CategoryAnalysis:
    def __init__(
        self, category: Optional[str] = None, java_runtime: Optional[str] = None
    ):
        self.category = category
        self.java_runtime = java_runtime

    @classmethod
    def from_json(cls, json_dict: dict):
        return cls(
            category=json_dict.get("category", None),
            java_runtime=json_dict.get("java_runtime", None),
        )

    def to_dict(self):
        return {
            "category": self.category,
            "java_runtime": self.java_runtime,
        }

    def to_json(self):
        return json.dumps(self.to_dict())

    def to_markdown(self):
        return (
            f"- **CVE category:** {self.category or 'N/A'}\n"
            f"- **Java Runtime:** {self.java_runtime or 'N/A'}"
        )

class ArchitectureAnalysis:
    def __init__(
        self,
        infrastructure_conditions: list[str] = [],
    ):
        self.infrastructure_conditions = infrastructure_conditions

    @classmethod
    def from_json(cls, json_dict: dict):
        return cls(
            infrastructure_conditions=json_dict.get(
                "infrastructure_conditions", []
            ),
        )

    def to_dict(self):
        return {
            "infrastructure_conditions": self.infrastructure_conditions,
        }

    def __str__(self):
        conditions_str = ", ".join(self.infrastructure_conditions)
        return f"Architecture Analysis:\n  Infrastructure Conditions: {conditions_str}"

    def to_markdown(self) -> str:
        conditions_markdown = "\n".join(
            [
                f"{i+1}. {condition}"
                for i, condition in enumerate(self.infrastructure_conditions)
            ]
        )
        return f"### Architecture Analysis\n\n**Details**:\n{conditions_markdown}\n"

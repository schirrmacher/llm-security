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

    def to_json(self):
        return {
            "infrastructure_conditions": self.infrastructure_conditions,
        }

    def __str__(self):
        conditions_str = ", ".join(self.infrastructure_conditions)
        return f"Architecture Analysis:\n  Infrastructure Conditions: {conditions_str}"

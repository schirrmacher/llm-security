class APISpecAnalysis:
    def __init__(
        self,
        critical: bool,
        explanation: str,
    ):
        self.critical = critical
        self.explanation = explanation

    @classmethod
    def from_json(cls, json_dict: dict):
        return cls(
            critical=json_dict.get("critical", False),
            explanation=json_dict.get("explanation", ""),
        )

    def to_json(self):
        return {
            "critical": self.critical,
            "explanation": self.explanation,
        }

    def __str__(self):
        return f"API Spec Analysis:\n  Critical: {self.critical}\n  Explanation: {self.explanation}"

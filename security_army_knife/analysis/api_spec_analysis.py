class APISpecAnalysis:
    def __init__(
        self,
        facilitates_attack: bool,
        explanation: str,
    ):
        self.facilitates_attack = facilitates_attack
        self.explanation = explanation

    @classmethod
    def from_json(cls, json_dict: dict):
        return cls(
            facilitates_attack=json_dict.get("facilitates_attack", False),
            explanation=json_dict.get("explanation", ""),
        )

    def to_json(self):
        return {
            "facilitates_attack": self.facilitates_attack,
            "explanation": self.explanation,
        }

    def __str__(self):
        return f"API Spec Analysis:\n  Facilitates Attack: {self.facilitates_attack}\n  Explanation: {self.explanation}"

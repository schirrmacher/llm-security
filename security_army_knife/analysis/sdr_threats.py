import yaml
from typing import List


class Threat:
    def __init__(
        self,
        threat: str,
        components: List[str],
        condition: str,
        score: int,
        mitigations: List[str],
    ):
        self.threat = threat
        self.components = components
        self.condition = condition
        self.score = score
        self.mitigations = mitigations

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            threat=data["threat"],
            components=data["components"],
            condition=data["condition"],
            score=data["score"],
            mitigations=data["mitigations"],
        )

    def to_dict(self) -> dict:
        return {
            "threat": self.threat,
            "components": self.components,
            "condition": self.condition,
            "score": self.score,
            "mitigations": self.mitigations,
        }

    def to_json(self) -> dict:
        return self.to_dict()

    def to_yaml(self) -> str:
        return yaml.dump(self.to_dict(), sort_keys=False)

    def to_markdown(self) -> str:
        mitigations_md = "\n".join(
            f"- {mitigation}" for mitigation in self.mitigations
        )
        return (
            f"### {self.threat}\n"
            f"- **Score**: {self.score}\n"
            f"- **Components**: {', '.join(self.components)}\n"
            f"- **Condition**: {self.condition}\n\n"
            f"Mitigations:\n{mitigations_md}\n"
        )


class SDRThreats:
    def __init__(self, threats: List[Threat]):
        self.threats = threats

    @classmethod
    def from_json(cls, json_data: dict):
        threats = [Threat.from_dict(threat) for threat in json_data["threats"]]
        return cls(threats)

    def to_dict(self) -> dict:
        return {"threats": [threat.to_dict() for threat in self.threats]}

    def to_json(self) -> dict:
        return self.to_dict()

    def to_yaml(self) -> str:
        return yaml.dump(self.to_dict(), sort_keys=False)

    def to_markdown(self) -> str:
        sorted_threats = sorted(
            self.threats, key=lambda threat: threat.score, reverse=True
        )
        return "\n".join(threat.to_markdown() for threat in sorted_threats)

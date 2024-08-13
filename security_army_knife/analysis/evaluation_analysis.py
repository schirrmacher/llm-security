class EvaluationAnalysis:
    def __init__(
        self, critical: bool, summary: str, threat_scenarios: list[str]
    ):
        self.critical = critical
        self.summary = summary
        self.threat_scenarios = threat_scenarios

    def to_dict(self):
        return {
            "critical": self.critical,
            "summary": self.summary,
            "threat_scenarios": self.threat_scenarios,
        }

    def to_markdown(self):
        """Convert the EvaluationAnalysis instance to a markdown string."""
        scenarios_md = "\n".join(
            f"- {scenario}" for scenario in self.threat_scenarios
        )
        return (
            f"## Final Analysis\n\n"
            f"**Critical:** {'Yes' if self.critical else 'No'}\n\n"
            f"**Summary:** {self.summary}\n\n"
            f"### Threat Scenarios\n"
            f"{scenarios_md}"
        )

    def __str__(self):
        """Return a human-readable string representation of the EvaluationAnalysis."""
        scenarios_str = "\n    ".join(self.threat_scenarios)
        return (
            f"Final Analysis:\n"
            f"  Critical: {self.critical}\n"
            f"  Summary: {self.summary}\n"
            f"  Threat Scenarios:\n    {scenarios_str}"
        )

    @classmethod
    def from_json(cls, json_data: dict):
        """Create an EvaluationAnalysis instance from a JSON dictionary."""
        return cls(
            critical=json_data.get("critical", False),
            summary=json_data.get("summary", "No summary provided."),
            threat_scenarios=json_data.get("threat_scenarios", []),
        )

    def to_markdown(self) -> str:
        threat_scenarios_str = "\n- ".join(self.threat_scenarios)
        return (
            f"### Evaluation Analysis\n\n"
            f"**Critical**: {'Yes' if self.critical else 'No'}\n\n"
            f"**Summary**:\n{self.summary}\n\n"
            f"**Threat Scenarios**:\n- {threat_scenarios_str}\n"
        )

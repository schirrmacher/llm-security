class EvaluationAnalysis:
    def __init__(self, severity: str, summary: str, threat_scenarios: list = None):
        self.severity = severity
        self.summary = summary
        self.threat_scenarios = threat_scenarios if threat_scenarios is not None else []

    def to_json(self):
        """Convert the EvaluationAnalysis instance to a JSON-serializable dictionary."""
        return {
            "severity": self.severity,
            "summary": self.summary,
            "threat_scenarios": self.threat_scenarios
        }

    def __str__(self):
        """Return a human-readable string representation of the EvaluationAnalysis."""
        return (
            f"Evaluation Analysis:\n"
            f"  Severity: {self.severity}\n"
            f"  Summary: {self.summary}\n"
            f"  Threat Scenarios: {', '.join(self.threat_scenarios)}"
        )

    @classmethod
    def from_json(cls, json_data: dict):
        """Create an EvaluationAnalysis instance from a JSON dictionary."""
        return cls(
            severity=json_data.get("severity", "Low"),
            summary=json_data.get("summary", "No summary provided."),
            threat_scenarios=json_data.get("threat_scenarios", [])
        )

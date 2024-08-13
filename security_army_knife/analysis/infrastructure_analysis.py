class InfrastructureAnalysis:
    def __init__(self, components: list[dict]):
        self.components = components

    def to_json(self):
        return {"components": self.components}

    def to_markdown(self):
        components_md = "\n".join(
            self._format_component_md(component)
            for component in self.components
        )
        return f"## Infrastructure Analysis\n\n{components_md}"

    def _format_component_md(self, component: dict) -> str:
        details = [
            f"**Name:** {component['name']}",
            f"**Type:** {component['type']}",
            f"**Public:** {'Yes' if component['public'] else 'No'}",
            f"**Explanation:** {component['explanation']}",
        ]

        if component.get("configurations"):
            details.append(
                f"**Configurations:** {', '.join(component['configurations'])}"
            )

        if component.get("ports"):
            details.append(f"**Ports:** {', '.join(component['ports'])}")

        if component.get("protocols"):
            details.append(
                f"**Protocols:** {', '.join(component['protocols'])}"
            )

        return "\n".join(details) + "\n"

    @classmethod
    def from_json(cls, json_data: dict):
        """Create an InfrastructureAnalysis instance from a JSON dictionary."""
        return cls(components=json_data.get("components", []))

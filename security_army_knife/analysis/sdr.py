import yaml
from typing import Optional
from security_army_knife.analysis.sdr_arch_analysis import SDRArchAnalysis
from security_army_knife.analysis.sdr_threats import SDRThreats


class SDR:
    def __init__(
        self,
        arch_analysis: Optional[SDRArchAnalysis] = None,
        threats: Optional[SDRThreats] = None,
    ):
        self.arch_analysis = arch_analysis
        self.threats = threats

    def to_dict(self) -> dict:
        return {
            "threats": self.threats.to_dict() if self.threats else None,
            "arch_analysis": (
                self.arch_analysis.to_dict() if self.arch_analysis else None
            ),
        }

    def to_json(self) -> dict:
        return self.to_dict()

    def to_yaml(self) -> str:
        return yaml.dump(self.to_dict(), sort_keys=False)

    @classmethod
    def from_json(cls, json_object: dict):
        arch_analysis = (
            SDRArchAnalysis.from_json(json_object["arch_analysis"])
            if json_object.get("arch_analysis")
            else None
        )
        threats = (
            SDRThreats.from_json(json_object["threats"])
            if json_object.get("threats")
            else None
        )
        return cls(arch_analysis=arch_analysis, threats=threats)

    def to_markdown(self) -> str:
        md_str = "# Security Design Review\n\n"
        if self.arch_analysis:
            md_str += self.arch_analysis.to_markdown()
        if self.threats:
            md_str += "## Threats\n"
            md_str += self.threats.to_markdown()
        return md_str

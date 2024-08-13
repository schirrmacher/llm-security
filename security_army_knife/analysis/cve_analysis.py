import json

from security_army_knife.analysis.code_analysis import CodeAnalysis
from security_army_knife.analysis.api_spec_analysis import APISpecAnalysis
from security_army_knife.analysis.architecture_analysis import (
    ArchitectureAnalysis,
)
from security_army_knife.analysis.evaluation_analysis import EvaluationAnalysis
from security_army_knife.analysis.infrastructure_analysis import (
    InfrastructureAnalysis,
)


class CVECategory:
    os = "os"
    distro = "distro"
    app = "app"
    unknown = "unknown"


class CVE:
    def __init__(
        self,
        name: str,
        description: str,
        category: str = CVECategory.unknown,
        code_analysis: CodeAnalysis = None,
        api_spec_analysis: APISpecAnalysis = None,
        architecture_analysis: ArchitectureAnalysis = None,
        final_analysis: EvaluationAnalysis = None,
    ):
        self.name = name
        self.description = description
        self.category = category
        self.code_analysis = code_analysis
        self.api_spec_analysis = api_spec_analysis
        self.architecture_analysis = architecture_analysis
        self.final_analysis = final_analysis

    @classmethod
    def from_json(cls, json_dict: dict):
        code_analysis_data = json_dict.get("code_analysis")
        code_analysis = (
            CodeAnalysis.from_json(code_analysis_data)
            if code_analysis_data
            else None
        )
        api_spec_data = json_dict.get("api_spec_analysis")
        api_spec_analysis = (
            APISpecAnalysis.from_json(api_spec_data) if api_spec_data else None
        )
        architecture_analysis_data = json_dict.get("architecture_analysis")
        architecture_analysis = (
            ArchitectureAnalysis.from_json(architecture_analysis_data)
            if architecture_analysis_data
            else None
        )
        final_analysis_data = json_dict.get("final_analysis")
        final_analysis = (
            EvaluationAnalysis(**final_analysis_data)
            if final_analysis_data
            else None
        )
        return cls(
            name=json_dict.get("name"),
            description=json_dict.get("description"),
            category=json_dict.get("category", CVECategory.unknown),
            code_analysis=code_analysis,
            api_spec_analysis=api_spec_analysis,
            architecture_analysis=architecture_analysis,
            final_analysis=final_analysis,
        )

    @classmethod
    def from_json_list(cls, json_list: list):
        return [cls.from_json(item) for item in json_list]

    def to_json(self):
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "code_analysis": (
                self.code_analysis.to_json() if self.code_analysis else None
            ),
            "api_spec_analysis": (
                self.api_spec_analysis.to_json()
                if self.api_spec_analysis
                else None
            ),
            "architecture_analysis": (
                self.architecture_analysis.to_json()
                if self.architecture_analysis
                else None
            ),
            "final_analysis": (
                self.final_analysis.to_json() if self.final_analysis else None
            ),
        }

    def to_markdown(self) -> str:
        sections = [
            f"# {self.name}\n\n",
            f"**Description**:\n{self.description}\n\n",
            f"**Category**: {self.category}\n\n",
            (
                self.api_spec_analysis.to_markdown()
                if self.api_spec_analysis
                else "No API Spec Analysis\n\n"
            ),
            (
                self.architecture_analysis.to_markdown()
                if self.architecture_analysis
                else "No Architecture Analysis\n\n"
            ),
            (
                self.final_analysis.to_markdown()
                if self.final_analysis
                else "No Final Analysis\n\n"
            ),
        ]
        return "\n".join(sections)

    def __str__(self):
        threat_scenarios = (
            "\n    ".join(self.final_analysis.threat_scenarios)
            if self.final_analysis and self.final_analysis.threat_scenarios
            else "No threat scenarios"
        )

        return (
            f"# CVE Name: {self.name}\n\n"
            f"**Description:** {self.description}\n\n"
            f"**Category:** {self.category}\n\n"
            f"## Code Analysis\n"
            f"{self.code_analysis or 'No Code Analysis'}\n\n"
            f"## API Spec Analysis\n"
            f"{self.api_spec_analysis or 'No API Spec Analysis'}\n\n"
            f"## Architecture Analysis\n"
            f"{self.architecture_analysis or 'No Architecture Analysis'}\n\n"
            f"## Final Analysis\n"
            f"**Critical:** {self.final_analysis.critical if self.final_analysis else 'No criticality'}\n\n"
            f"**Summary:** {self.final_analysis.summary if self.final_analysis else 'No summary'}\n\n"
            f"**Threat Scenarios:**\n\n"
            f"{threat_scenarios}"
        )


class CVEAnalysis:
    def __init__(
        self,
        cves: list[CVE] = [],
        infrastructure_analysis: InfrastructureAnalysis = None,
    ):
        self.cves = cves
        self.infrastructure_analysis = infrastructure_analysis

    @classmethod
    def from_json(cls, json_dict: dict):
        cve_list = CVE.from_json_list(json_dict.get("cves", []))
        infrastructure_analysis = InfrastructureAnalysis.from_json(
            json_dict.get("infrastructure_analysis", {})
        )
        return cls(
            cves=cve_list, infrastructure_analysis=infrastructure_analysis
        )

    def to_json(self):
        return {
            "cves": [cve.to_json() for cve in self.cves],
            "infrastructure_analysis": (
                self.infrastructure_analysis.to_json()
                if self.infrastructure_analysis
                else {}
            ),
        }

    def to_markdown(self) -> str:
        markdown_content = "\n\n".join([cve.to_markdown() for cve in self.cves])
        infrastructure_md = (
            self.infrastructure_analysis.to_markdown()
            if self.infrastructure_analysis
            else ""
        )
        return f"{markdown_content}\n\n{infrastructure_md}"

    def save_to_file(self, file_path: str):
        with open(file_path, "w") as file:
            json.dump(self.to_json(), file, indent=4)

    @staticmethod
    def load_state(file_path: str) -> "CVEAnalysis":
        try:
            with open(file_path, "r") as file:
                state = json.load(file)
                return CVEAnalysis.from_json(state)
        except Exception as e:
            return CVEAnalysis()

    @staticmethod
    def merge_cves(existing_cves: list[CVE], new_cves: list[CVE]) -> list[CVE]:
        new_cve_dict = {cve.name: cve for cve in new_cves}

        for existing_cve in existing_cves:
            if existing_cve.name in new_cve_dict:
                new_cve_dict[existing_cve.name] = existing_cve
            else:
                new_cve_dict[existing_cve.name] = existing_cve

        return list(new_cve_dict.values())

    @staticmethod
    def load_and_merge_state(
        file_path: str, new_cves: list[CVE]
    ) -> "CVEAnalysis":
        cve_analysis = CVEAnalysis.load_state(file_path)
        cve_analysis.cves = CVEAnalysis.merge_cves(cve_analysis.cves, new_cves)
        return cve_analysis

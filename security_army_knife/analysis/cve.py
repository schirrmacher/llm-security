import json

from security_army_knife.analysis.code_analysis import CodeAnalysis
from security_army_knife.analysis.api_spec_analysis import APISpecAnalysis
from security_army_knife.analysis.architecture_analysis import (
    ArchitectureAnalysis,
)
from security_army_knife.analysis.evaluation_analysis import EvaluationAnalysis


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
            self.api_spec_analysis.to_markdown() if self.api_spec_analysis else "No API Spec Analysis\n\n",
            self.architecture_analysis.to_markdown() if self.architecture_analysis else "No Architecture Analysis\n\n",
            self.final_analysis.to_markdown() if self.final_analysis else "No Final Analysis\n\n",
        ]
        return "\n".join(sections)
    
    def __str__(self):
        threat_scenarios = (
            "\n    ".join(self.final_analysis.threat_scenarios)
            if self.final_analysis and self.final_analysis.threat_scenarios
            else "No threat scenarios"
        )

        return (
            f"CVE Name: {self.name}\n"
            f"Description: {self.description}\n"
            f"Category: {self.category}\n"
            f"{self.code_analysis or 'No Code Analysis'}\n"
            f"{self.api_spec_analysis or 'No API Spec Analysis'}\n"
            f"{self.architecture_analysis or 'No Architecture Analysis'}\n"
            f"Final Analysis:\n"
            f"  Critical: {self.final_analysis.critical if self.final_analysis else 'No criticality'}\n"
            f"  Summary: {self.final_analysis.summary if self.final_analysis else 'No summary'}\n"
            f"Threat Scenarios:\n    {threat_scenarios}"
        )

    @staticmethod
    def persist_state(cve_list: list["CVE"], file_path: str):
        with open(file_path, "w") as file:
            json.dump([cve.to_json() for cve in cve_list], file, indent=4)

    @staticmethod
    def load_state(file_path: str) -> list:
        try:
            with open(file_path, "r") as file:
                cve_list = json.load(file)
                return CVE.from_json_list(cve_list)
        except (IOError, json.JSONDecodeError, TypeError) as e:
            # Log the error if needed, e.g., print(e) or use a logging framework
            return []

    @staticmethod
    def merge_cves(existing_cves: list, new_cves: list) -> list:
        # Prefer to use existing CVEs because they might have been analyzed already
        new_cve_dict = {cve.name: cve for cve in new_cves}

        for existing_cve in existing_cves:
            if existing_cve.name in new_cve_dict:
                new_cve_dict[existing_cve.name] = existing_cve
            else:
                new_cve_dict[existing_cve.name] = existing_cve

        return list(new_cve_dict.values())

    @staticmethod
    def load_and_merge_state(file_path: str, new_cves: list) -> list:
        existing_cves = CVE.load_state(file_path)
        merged_cves = CVE.merge_cves(existing_cves, new_cves)
        CVE.persist_state(merged_cves, file_path)
        return merged_cves

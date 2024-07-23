import json

from security_army_knife.analysis.code_analysis import CodeAnalysis


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
    ):
        self.name = name
        self.description = description
        self.category = category
        self.code_analysis = code_analysis

    @classmethod
    def from_json(cls, json_dict: dict):
        code_analysis_data = json_dict.get("code_analysis")
        code_analysis = (
            CodeAnalysis.from_json(code_analysis_data)
            if code_analysis_data
            else None
        )
        return cls(
            name=json_dict.get("name"),
            description=json_dict.get("description"),
            category=json_dict.get("category", CVECategory.unknown),
            code_analysis=code_analysis,
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
        }

    def __str__(self):
        return (
            f"CVE Name: {self.name}\n"
            f"Description: {self.description}\n"
            f"Category: {self.category}\n"
            f"{self.code_analysis or 'No Code Analysis'}"
        )

    @staticmethod
    def persist_state(cves: list, file_path: str):
        with open(file_path, "w") as file:
            json.dump([cve.to_json() for cve in cves], file, indent=4)

    @staticmethod
    def load_state(file_path: str) -> list:
        with open(file_path, "r") as file:
            cve_list = json.load(file)
            return CVE.from_json_list(cve_list)

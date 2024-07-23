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
    def persist_state(cve_list: list["CVE"], file_path: str):
        with open(file_path, "w") as file:
            json.dump([cve.to_json() for cve in cve_list], file, indent=4)

    @staticmethod
    def load_state(file_path: str) -> list:
        with open(file_path, "r") as file:
            cve_list = json.load(file)
            return CVE.from_json_list(cve_list)

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

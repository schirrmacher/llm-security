import json
from typing import List

from security_army_knife.cve_categorizer_agent import CategorizedCVE
from security_army_knife.application_agent import ApplicationCVE


class StateHandler:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.categorized_cves: List[CategorizedCVE] = None
        self.application_cves: List[ApplicationCVE] = None
        self.load_data()

    def load_data(self):
        try:
            with open(self.file_path, "r") as file:
                data = json.load(file)
                self.categorized_cves = (
                    [
                        CategorizedCVE.from_json(item)
                        for item in data.get("categorized_cves", [])
                    ]
                    if "categorized_cves" in data
                    else []
                )
                self.application_cves = (
                    [
                        ApplicationCVE.from_json(item)
                        for item in data.get("application_cves", [])
                    ]
                    if "application_cves" in data
                    else []
                )
        except FileNotFoundError:
            self.categorized_cves = []
            self.application_cves = []
        except json.JSONDecodeError:
            self.categorized_cves = []
            self.application_cves = []

    def get_categorized_cves(self) -> List[CategorizedCVE]:
        return self.categorized_cves

    def get_application_cves(self) -> List[ApplicationCVE]:
        return self.application_cves

    def store_categorized_cves(self, categorized_cves: List[CategorizedCVE]):
        self.categorized_cves = categorized_cves
        self.save_data()

    def store_application_cves(self, application_cves: List[ApplicationCVE]):
        self.application_cves = application_cves
        self.save_data()

    def save_data(self):
        data = {
            "categorized_cves": (
                [cve.to_json() for cve in self.categorized_cves]
                if self.categorized_cves
                else []
            ),
            "application_cves": (
                [cve.to_json() for cve in self.application_cves]
                if self.application_cves
                else []
            ),
        }
        with open(self.file_path, "w") as file:
            json.dump(data, file, indent=4)

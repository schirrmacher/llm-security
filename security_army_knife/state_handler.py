import json

from security_army_knife.cve import CVE
from security_army_knife.cve_categorizer_agent import CategorizedCVE
from security_army_knife.application_agent import ApplicationCVE


class StateHandler:
    def __init__(self, file_path: str, input_cves: list[CVE]):
        self.file_path = file_path
        self.input_cves: list[CVE] = input_cves
        self.categorized_cves, self.application_cves = self.load_data(file_path)

    def load_data(self, file_path):
        categorized_cves = []
        application_cves = []
        try:
            with open(file_path, "r") as file:
                data = json.load(file)
                categorized_cves = [
                    CategorizedCVE.from_json(item)
                    for item in data.get("categorized_cves", [])
                ]
                application_cves = [
                    ApplicationCVE.from_json(item)
                    for item in data.get("application_cves", [])
                ]
        except FileNotFoundError:
            categorized_cves = []
            application_cves = []
        except json.JSONDecodeError:
            categorized_cves = []
            application_cves = []
        return categorized_cves, application_cves

    def _get_diff(self, cve_list: list[CVE], analyzed_cves: list[CVE]):
        analyzed_cve_list_names = [cve.name for cve in analyzed_cves]
        return list(
            filter(
                lambda cve: cve.name not in analyzed_cve_list_names,
                cve_list,
            )
        )

    def get_cves_to_be_categorized(self) -> list[CategorizedCVE]:
        return self._get_diff(
            cve_list=self.input_cves, analyzed_cves=self.categorized_cves
        )

    def get_application_cves_to_be_analyzed(self) -> list[ApplicationCVE]:
        return self._get_diff(
            cve_list=self.categorized_cves,
            analyzed_cves=self.application_cves,
        )

    def _remove_duplicate_cves(self, cve_list: list[CVE]):
        seen = set()
        unique_cves = []
        for cve in cve_list:
            if cve.name not in seen:
                unique_cves.append(cve)
                seen.add(cve.name)
        return unique_cves

    def store_categorized_cves(
        self, new_categorized_cves: list[CategorizedCVE]
    ) -> list[CategorizedCVE]:
        all_categorized_cves = self._remove_duplicate_cves(
            self.categorized_cves + new_categorized_cves
        )
        self.save_data(
            categorized_cves=all_categorized_cves,
            application_cves=self.application_cves,
        )
        self.categorized_cves = all_categorized_cves
        return all_categorized_cves

    def store_application_cves(
        self, new_application_cves: list[ApplicationCVE]
    ) -> list[ApplicationCVE]:
        all_application_cves = self._remove_duplicate_cves(
            self.application_cves + new_application_cves
        )
        self.save_data(
            categorized_cves=self.categorized_cves,
            application_cves=all_application_cves,
        )
        return all_application_cves

    def save_data(
        self,
        categorized_cves: list[CategorizedCVE],
        application_cves: list[ApplicationCVE],
    ):
        data = {
            "categorized_cves": [cve.to_json() for cve in categorized_cves],
            "application_cves": [cve.to_json() for cve in application_cves],
        }
        with open(self.file_path, "w") as file:
            json.dump(data, file, indent=4)

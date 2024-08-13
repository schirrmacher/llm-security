import json
from typing import List, Dict, Any

from security_army_knife.analysis.cve_analysis import CVE


class TrivyImporter:
    def __init__(self, json_file: str):
        self.json_file = json_file
        self.data = self.read_json_file()

    def read_json_file(self) -> Dict[str, Any]:
        with open(self.json_file, "r") as file:
            return json.load(file)

    def _get_schema_version(self) -> int:
        return self.data.get("SchemaVersion", None)

    def _get_artifact_name(self) -> str:
        return self.data.get("ArtifactName", None)

    def _get_artifact_type(self) -> str:
        return self.data.get("ArtifactType", None)

    def _get_os_info(self) -> Dict[str, str]:
        return self.data.get("Metadata", {}).get("OS", {})

    def _get_image_id(self) -> str:
        return self.data.get("Metadata", {}).get("ImageID", None)

    def _get_diff_ids(self) -> List[str]:
        return self.data.get("Metadata", {}).get("DiffIDs", [])

    def _get_repo_tags(self) -> List[str]:
        return self.data.get("Metadata", {}).get("RepoTags", [])

    def _get_repo_digests(self) -> List[str]:
        return self.data.get("Metadata", {}).get("RepoDigests", [])

    def _get_image_config(self) -> Dict[str, Any]:
        return self.data.get("Metadata", {}).get("ImageConfig", {})

    def _get_results(self) -> List[Dict[str, Any]]:
        return self.data.get("Results", [])

    def _get_vulnerabilities(self) -> List[Dict[str, Any]]:
        vulnerabilities = []
        for result in self._get_results():
            if "Vulnerabilities" in result:
                vulnerabilities.extend(result["Vulnerabilities"])
        return vulnerabilities

    def get_cves(self) -> List[CVE]:
        cve_objects = []
        for vulnerability in self._get_vulnerabilities():
            cve_object = CVE(
                name=vulnerability.get("VulnerabilityID"),
                description=vulnerability.get("Description"),
            )
            cve_objects.append(cve_object)
        return cve_objects

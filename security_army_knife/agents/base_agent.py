from security_army_knife.cve import CVE
from security_army_knife.base_model import BaseModel


class BaseAgent:

    dependencies: list[str]

    def __init__(self, model: BaseModel, dependencies: list[str] = []):
        self.model = model
        self.dependencies = dependencies

    def analyze(self, cve_list: list[CVE]) -> list[CVE]:
        pass

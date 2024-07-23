from typing import Callable

from security_army_knife.analysis.cve import CVE
from security_army_knife.base_model import BaseModel


class BaseAgent:

    dependencies: list[str]

    def __init__(self, model: BaseModel, dependencies: list[str] = []):
        self.model = model
        self.dependencies = dependencies

    def analyze(
        self,
        cve_list: list[CVE],
        before_cve_analyzed: Callable[[CVE], None],
        after_cve_analyzed: Callable[[CVE], None],
        when_cve_skipped: Callable[[CVE], None],
    ) -> list[CVE]:
        for cve in cve_list:
            before_cve_analyzed(cve)
            after_cve_analyzed(cve)
        return cve_list

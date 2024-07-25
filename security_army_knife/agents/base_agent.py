from typing import Callable, Type

from security_army_knife.analysis.cve import CVE
from security_army_knife.base_model import BaseModel


class AgentEventType:
    INFORMATION = "INFORMATION"
    BEFORE_CVE_ANALYSIS = "BEFORE_CVE_ANALYSIS"
    AFTER_CVE_ANALYSIS = "AFTER_CVE_ANALYSIS"


class AgentEvent:
    def __init__(
        self,
        event_type: AgentEventType,
        cve: CVE,
        message: str = "",
    ):
        self.event_type = event_type
        self.cve = cve
        self.message = message


class BaseAgent:

    dependencies: list[Type]

    def __init__(self, model: BaseModel, dependencies: list[str] = []):
        self.model = model
        self.dependencies = dependencies

    def analyze(
        self,
        cve_list: list[CVE],
        handle_event: Callable[[AgentEvent], None],
    ) -> list[CVE]:
        return cve_list

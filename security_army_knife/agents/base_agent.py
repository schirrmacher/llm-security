from enum import Enum
from typing import Callable, Type

from security_army_knife.analysis.cve import CVE
from security_army_knife.base_model import BaseModel


class AgentEvent:

    class Type(Enum):
        REQUEST = "REQUEST"
        RESPONSE = "RESPONSE"
        INFORMATION = "INFORMATION"
        BEFORE_ANALYSIS = "BEFORE_ANALYSIS"
        AFTER_ANALYSIS = "AFTER_ANALYSIS"
        ERROR = "ERROR"

    def __init__(
        self,
        event_type: Type,
        cve: CVE,
        message: str = "",
    ):
        self.event_type = event_type
        self.cve = cve
        self.message = message


class CachedEvent(AgentEvent):

    def __init__(self, cve: CVE):
        super(CachedEvent, self).__init__(
            event_type=AgentEvent.Type.INFORMATION,
            cve=cve,
            message="cached",
        )


class ErrorEvent(AgentEvent):

    error: Exception

    def __init__(self, cve: CVE, error: Exception):
        super(ErrorEvent, self).__init__(
            event_type=AgentEvent.Type.ERROR,
            cve=cve,
            message=f"skipped analysis, due to error {error}",
        )
        self.error = error


class BeforeAnalysis(AgentEvent):

    def __init__(self, cve: CVE):
        super(BeforeAnalysis, self).__init__(
            event_type=AgentEvent.Type.BEFORE_ANALYSIS,
            cve=cve,
        )


class AfterAnalysis(AgentEvent):

    def __init__(self, cve: CVE):
        super(AfterAnalysis, self).__init__(
            event_type=AgentEvent.Type.AFTER_ANALYSIS,
            cve=cve,
        )


class InformationEvent(AgentEvent):

    def __init__(self, cve: CVE, message: str):
        super(InformationEvent, self).__init__(
            event_type=AgentEvent.Type.INFORMATION, cve=cve, message=message
        )


class RequestEvent(AgentEvent):

    def __init__(self, cve: CVE, message: str = ""):
        super(RequestEvent, self).__init__(
            event_type=AgentEvent.Type.REQUEST, cve=cve, message=message
        )


class ResponseEvent(AgentEvent):

    def __init__(self, cve: CVE, message: str):
        super(ResponseEvent, self).__init__(
            event_type=AgentEvent.Type.RESPONSE, cve=cve, message=message
        )


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

from enum import Enum
from typing import Callable, Type, Optional

from security_army_knife.analysis.cve_analysis import CVE
from security_army_knife.analysis.sdr import SDR
from security_army_knife.models.base_model import BaseModel


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
        cve: Optional[CVE] = None,
        sdr: Optional[SDR] = None,
        message: str = "",
    ):
        self.event_type = event_type
        self.cve = cve
        self.sdr = sdr
        self.message = message


class CachedEvent(AgentEvent):

    def __init__(self, cve: Optional[CVE] = None, sdr: Optional[SDR] = None):
        super(CachedEvent, self).__init__(
            event_type=AgentEvent.Type.INFORMATION,
            cve=cve,
            sdr=sdr,
            message="cached",
        )


class ErrorEvent(AgentEvent):

    error: Exception

    def __init__(
        self,
        error: Exception,
        cve: Optional[CVE] = None,
        sdr: Optional[SDR] = None,
    ):
        super(ErrorEvent, self).__init__(
            event_type=AgentEvent.Type.ERROR,
            cve=cve,
            sdr=sdr,
            message=f"skipped analysis, due to error {error}",
        )
        self.error = error


class BeforeAnalysis(AgentEvent):

    def __init__(
        self, cve: Optional[CVE] = None, sdr: Optional[SDR] = None, message=""
    ):
        super(BeforeAnalysis, self).__init__(
            event_type=AgentEvent.Type.BEFORE_ANALYSIS,
            cve=cve,
            sdr=sdr,
            message=message,
        )


class AfterAnalysis(AgentEvent):

    def __init__(
        self, cve: Optional[CVE] = None, sdr: Optional[SDR] = None, message=""
    ):
        super(AfterAnalysis, self).__init__(
            event_type=AgentEvent.Type.AFTER_ANALYSIS,
            cve=cve,
            sdr=sdr,
            message=message,
        )


class InformationEvent(AgentEvent):

    def __init__(
        self, message: str, cve: Optional[CVE] = None, sdr: Optional[SDR] = None
    ):
        super(InformationEvent, self).__init__(
            event_type=AgentEvent.Type.INFORMATION,
            cve=cve,
            sdr=sdr,
            message=message,
        )


class RequestEvent(AgentEvent):

    def __init__(
        self,
        message: str = "",
        cve: Optional[CVE] = None,
        sdr: Optional[SDR] = None,
    ):
        super(RequestEvent, self).__init__(
            event_type=AgentEvent.Type.REQUEST,
            cve=cve,
            sdr=sdr,
            message=message,
        )


class ResponseEvent(AgentEvent):

    def __init__(
        self,
        message: str = "",
        cve: Optional[CVE] = None,
        sdr: Optional[SDR] = None,
    ):
        super(ResponseEvent, self).__init__(
            event_type=AgentEvent.Type.RESPONSE,
            cve=cve,
            sdr=sdr,
            message=message,
        )


class BaseAgent:

    dependencies: list[Type]

    def __init__(self, model: BaseModel, dependencies: list[str] = []):
        self.model = model
        self.dependencies = dependencies

    def analyze(
        self,
        handle_event: Callable[[AgentEvent], None],
    ) -> None:
        return None

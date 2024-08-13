from typing import Callable, Type

from security_army_knife.analysis.cve_analysis import CVEAnalysis
from security_army_knife.models.base_model import BaseModel
from security_army_knife.agents.base_agent import BaseAgent, AgentEvent


class BaseCVEAgent(BaseAgent):

    dependencies: list[Type]

    def __init__(self, model: BaseModel, dependencies: list[str] = []):
        self.model = model
        self.dependencies = dependencies

    def analyze(
        self,
        analysis: CVEAnalysis,
        handle_event: Callable[[AgentEvent], None],
    ) -> CVEAnalysis:
        return analysis

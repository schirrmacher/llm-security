import json
from typing import Type, TextIO, Optional, Callable

from llama_index.core.llms import ChatMessage
from security_army_knife.agents.base_agent import (
    BaseAgent,
    AgentEvent as Event,
    RequestEvent,
    ResponseEvent,
    InformationEvent,
    ErrorEvent,
)
from security_army_knife.analysis.sdr import SDR
from security_army_knife.agents.sdr_arch_agent import SDRArchAnalysis
from security_army_knife.models.base_model import BaseModel
from security_army_knife.analysis.sdr_arch_analysis import SDRArchAnalysis
from security_army_knife.analysis.sdr_threats import SDRThreats


class SDRThreatAgent(BaseAgent):

    dependencies: list[Type] = [SDRArchAnalysis]

    def __init__(
        self,
        model: BaseModel,
        architecture_diagram: Optional[TextIO],
        api_documentation: Optional[TextIO],
    ):
        super().__init__(model=model)
        self.architecture_diagram = architecture_diagram
        self.api_documentation = api_documentation

    def analyze(
        self,
        handle_event: Callable[[Event], None],
        target: SDR,
    ) -> SDR:

        if not target.arch_analysis:
            return target

        task = f"""
        # Introduction
        - You are a system security expert and hacker.

        # Tasks
        - Work on the following tasks.
        - Do not repeat this description in your response.
        - If data is not mentioned in the diagram apply the value 'MISSING'.

        ## Identify Threats
        - Identify as many threats as possible
        - List the assets affected by the threat
        - Identify which components are affected by the threat
        - Mention which components are affected and explain in detail under what conditions the threat occurs
        - Include the knowledge of OWASP Top 10
        - Assign a risks score from 1 (not critical) to 25 (critical)

        ### General Threats
        - For databases consider missing backup mechanisms
        - For key material consider leakage and expiry scenarios
        - For authentication protocols consider missing validation of roles and permissions
        - For public entry points consider DDoS attacks, especially if compute intensive operations might be triggered
        - For transfer of file formats consider security attributes like confidentiality, integrity, authenticity

        ### Threat Score Evaluation
        - Consider DDoS attacks as highly critical
        - Consider authentication failures as highly critical

        ## Mitigations
        - For each threat propose a set of mitigations

        ## Summary
        - Create a JSON object with the following attributes:
        ```
        threats:
            - threat: Some explanation
                components: 
                - Client
                - Server
                - Protocol
                condition: What technical conditions must be given
                score: 4
                mitigations:
                - mitigation 1
                - mitigation 2
            - threat: Some other explanation
                components:
                - Client
                - Server
                condition: What technical conditions must be given
                score: 12
                mitigations:
                - mitigation 3
                - mitigation 4
            - threat: Some other explanation
                components:
                - Client
                condition: What technical conditions must be given
                score: 1
                mitigations:
                - mitigation 3
                - mitigation 4
        ```

        # System to Be Analyzed

        ```
        {target.arch_analysis.to_yaml()}
        ```
        """

        messages = [
            ChatMessage(
                role="user",
                content=task,
            ),
        ]

        try:
            handle_event(RequestEvent(None))
            response = self.model.talk(messages, json=True)
            handle_event(ResponseEvent(None, message=response.message.content))

            json_object = json.loads(response.message.content)
            target.threats = SDRThreats.from_json(json_object)

            handle_event(
                InformationEvent(
                    sdr=target,
                    message=f"{len(target.threats.threats)} threats identified",
                )
            )

        except Exception as e:
            handle_event(ErrorEvent(sdr=target, error=e))

        return target

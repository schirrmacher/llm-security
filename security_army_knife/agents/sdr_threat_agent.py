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
        prompt_path: Optional[str] = None,
    ):
        super().__init__(model=model)
        self.architecture_diagram = architecture_diagram
        self.prompt_path = prompt_path

    def _read_task_prompt(self, prompt_path: str) -> str:
        if not prompt_path:
            raise ValueError("No task file path provided.")

        with open(prompt_path, "r") as file:
            task_prompt = file.read()

        return task_prompt

    def analyze(
        self,
        handle_event: Callable[[Event], None],
        target: SDR,
    ) -> SDR:

        try:
            prompt = self._read_task_prompt(self.prompt_path)
        except Exception as e:
            handle_event(
                ErrorEvent(sdr=target, error=f"Failed to read task file: {e}")
            )
            return target

        if not target.arch_analysis:
            return target

        task = f"""

        # Introduction

        - You are a system security expert and hacker.
        - You have experience with Advanced Persistent Threat actors
        - You have knowledge about OWASP Top 10 and MITRE ATT&CK

        # Tasks

        - Work on the following tasks and consider the system architecture below.
        - Do not repeat this description in your response.
        - If data is not mentioned in the diagram apply the value 'MISSING'.

        # Identify Threats

        - Identify as many threats as possible
        - YOU MUST COME UP WITH MORE THAN 15 THREATS IN THE RESPONSE!!!
        - List the assets affected by the threat
        - Identify which components are affected by the threat
        - Explain a potential scenarios how the threat might affect the assets and components
        - You must omit the threats if they do not affect the described assets or components in the system below

        # Threat Score

        - Assign a risks score from 1 (not critical) to 25 (critical)
        - Consider DDoS attacks as highly critical
        - Consider authentication failures as highly critical

        ## Attack Scenarios

        - For each threat explain a scenario how the threat becomes reality
        - You must explicitly mention the affected asset!
        - You must explicitly explain how system components are misused or circumvented in a given scenario!

        {prompt}

        # Mitigations

        - For each threat propose mitigations
        - Mitigations describe how to prevent the mentioned threat
        - Add a link to documentation (references) if applicable so engineers know how to solve a particular problem

        # Summary
        - Create a JSON object with the following attributes:
        ```
        threats:
            - threat: Some explanation
                components: 
                - Client
                - Server
                - Protocol
                scenario: Describe how a scenario looks like for the threat
                score: 4
                mitigations:
                - mitigation 1
                - mitigation 2
            - threat: Some other explanation
                components:
                - Client
                - Server
                scenario: Describe how a scenario looks like for the threat
                score: 12
                mitigations:
                - mitigation 3
                - mitigation 4
            - threat: Some other explanation
                components:
                - Client
                scenario: Describe how a scenario looks like for the threat
                score: 1
                mitigations:
                - mitigation 3
                - mitigation 4
        ```

        # System to be Analyzed for Threats

        ``
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
            handle_event(RequestEvent(sdr=target))
            response = self.model.talk(messages, json=True)
            handle_event(ResponseEvent(sdr=target))

            json_object = json.loads(response.message.content)

            threats = SDRThreats.from_json(json_object)

            handle_event(
                InformationEvent(
                    sdr=target,
                    message=f"{len(threats.threats)} threats identified",
                )
            )

            if target.threats is None:
                target.threats = threats
            else:
                target.threats.threats.extend(threats.threats)

        except Exception as e:
            handle_event(ErrorEvent(sdr=target, error=e))

        return target

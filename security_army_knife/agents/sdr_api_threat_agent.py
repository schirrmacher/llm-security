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
from security_army_knife.models.base_model import BaseModel
from security_army_knife.analysis.sdr_arch_analysis import SDRArchAnalysis
from security_army_knife.analysis.sdr_threats import SDRThreats


class SDRApiThreatAgent(BaseAgent):

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
        - You are a system security expert and hacker
        - You focus on API and endpoint security
        - You have experience with Advanced Persistent Threat actors
        - You have knowledge about OWASP Top 10 and MITRE ATT&CK

        # Tasks
        - Identify as many threats as possible.
        - Do not repeat this description in your response.
        - If the system below does not mention entrypoints you must not derive threats!
        - Focus on the entrypoints to the system.

        # System to be Analyzed for Threats
        - The following is the system you have to analyze
        ``
        {target.arch_analysis.to_yaml()}
        ```

        ## Identify Threats for Entrypoints of the System
        - Identify as many threats as possible
        - List the assets affected by the threat
        - Identify which components are affected by the threat
        - Explain a potential scenarios how the threat might affect the assets and components
        - You must omit the threats if they do not affect the described assets or components in the system below

        ## OAuth Threats
        - Only if you identify OAuth consider the following:
            - Apply “Proof Key for Code Exchange by OAuth Public Clients” (PKCE)
            - Do never apply: Implicit flow and Resource Owner Password Credentials flow, since those are considered as insecure
        - Do not consider those threats when OAuth is not present in the system

        ## JSON Web Token Threats
        - Only if you identify JWT consider the following:
            - Do not apply custom signature validation and apply mature and popular validation libraries
            - Properly evaluate token claims to prevent cross user attacks
            - Create e2e tests for unhappy paths, invalid tokens was provided
            - Make use of sender-constrained access tokens and sender-constrained rate limiting
            - Restrict privileges associated with an Access Token to the minimum required
            - Monitor usage of invalid tokens
            - Rotate JWT signing keys after 90 days
            - Set short Access Token expiry, vary on Refresh Token expiry
        - Do not consider those threats when JWT is not present in the system

        ## HTTP Threats
        - Only if you identify HTTP consider the following:
            - Path Traversal attacks: aim is to access files and directories that are stored outside the web root folder
            - HTTP flood DDoS attack: utilizes the disparity in relative resource consumption, by sending many post requests directly to a targeted server until it's capacity is saturated
        - Do not consider those threats when HTTP is not present in the system

        ## MQTT Threats
        - Only if you identify MQTT consider the following:
            - Exploits of MQTT session handling
            - Exploits of MQTT parameter shuffling
        - Do not consider those threats when MQTT is not present in the system

        ## Exclusion of Threats
        - You must not include a threat if you do not identify the associated technology

        ### Threat Score
        - Assign a risks score from 1 (not critical) to 25 (critical)
        - Consider DDoS attacks as highly critical
        - Consider authentication failures as highly critical

        ### Attack Scenarios
        - For each threat explain a scenario how the threat becomes reality
        - You must explicitly mention the affected asset!
        - You must explicitly explain how system components are misused or circumvented in a given scenario!
        - Example: Since the system exposes public API endpoints, missing security monitoring might allow attackers to perform brute-force attacks on the APIs unnoticed

        ## Mitigations
        - For each threat propose a set of mitigations
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

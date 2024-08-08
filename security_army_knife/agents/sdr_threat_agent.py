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
        - You have experience with Advanced Persistent Threat actors
        - You have knowledge about OWASP Top 10 and MITRE ATT&CK

        # Tasks
        - Work on the following tasks and consider the system architecture below.
        - Do not repeat this description in your response.
        - If data is not mentioned in the diagram apply the value 'MISSING'.

        ## Identify Threats
        - Identify as many threats as possible
        - List the assets affected by the threat
        - Identify which components are affected by the threat
        - Create at least 20 threats with focus on the assets and the affected components
        - Explain a potential scenarios how the threat might affect the assets and components
        - You must omit the threats if they do not affect the described assets or components in the system below

        ### Threat Score
        - Assign a risks score from 1 (not critical) to 25 (critical)
        - Consider DDoS attacks as highly critical
        - Consider authentication failures as highly critical

        ### Attack Scenarios
        - For each threat explain a scenario how the threat becomes reality
        - You must explicitly mention the affected asset!
        - You must explicitly explain how system components are misused or circumvented in a given scenario!
        - Example: Since the system exposes public API endpoints, missing security monitoring might allow attackers to perform brute-force attacks on the APIs unnoticed

        ### General Threats
        - For key material consider leakage and expiry scenarios
        - For public entry points consider DDoS attacks, especially if compute intensive operations might be triggered
        - For transfer of file formats consider security attributes like confidentiality, integrity, authenticity
        - Missing security monitoring and logging

        ### Persistence Related Threats
        - For databases consider missing backup mechanisms
        - Consider that sensitive data, like credit cards and passwords, are encrypted at rest

        ### Authentication Threats
        - For authentication protocols consider missing validation of roles and permissions
        - Make sure that each participant in a system can only access the data which she should have access to
        - If OAuth/OpenID with JWT is applied, make sure to validate the claims in every stage of critical operations
        - Apply the least privilege principle
        - For all authentication threats consider e2e tests as mitigation which are testing the unhappy path (invalid authentication attempt)

        ### Mobile Application Threats
        - For mobile applications, like Android or iOS, consider the following threats
        - You must not mention the threats if they do not affect the described system below
        - Challenge if sensitive key material is stored in secure enclaves
        - Challenge if APIs offer proper bot protection to prevent automated attacks
        - Only list the above when you identify mobile app technologies (iOS, Android etc.)!

        ### Vendor and Third-party Threats
        - Consider security issues in third-party components
        - Consider information stealer malware in dependencies and challenge firewall setups
        - Mitigation is to review source code of third-party components and perform vulnerability scans

        ### Browser Related Threats
        - The must only consider the threats when you are really sure that browser based technologies (JavaScript, HTML, Angular, React etc.) are applied in the system below!
        - Consider proper settings of the same-origin policy (SOP) for Cross-origin resource sharing (CORS)
        - Consider proper sanitization to prevent Cross-Site Scripting (XSS) attacks
        - Consider the threat of Cross-Site Request Forgery (CSRF)
        - Consider Server-Side Request Forgery Attacks (SSRF) which exploits flaws in web applications to access internal resources

        ## Mitigations
        - For each threat propose a set of mitigations
        - Add a link to documentation (references) if applicable so engineers know how to solve a particular problem

        ## References
        - Add this for monitoring and alerting related mitigations: https://paymenttools.atlassian.net/wiki/spaces/ARCH/pages/1570963461/Security+Guide
        - Add this for authentication related mitigations: https://paymenttools.atlassian.net/wiki/spaces/ARCH/pages/1323663361/DRAFT+Authentication+Authorization+Guide

        ## Summary
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

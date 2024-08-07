from typing import Type, TextIO, Optional, Callable

from llama_index.core.llms import ChatMessage
from security_army_knife.agents.base_agent import (
    BaseAgent,
    AgentEvent as Event,
    RequestEvent,
    ResponseEvent,
    ErrorEvent,
)
from security_army_knife.base_model import BaseModel
from security_army_knife.analysis.sdr import SDR


class ThreatAgent(BaseAgent):

    dependencies: list[Type] = []

    def __init__(self, model: BaseModel):
        super().__init__(model=model)

    def analyze(
        self,
        handle_event: Callable[[Event], None],
        architecture_diagram: Optional[TextIO],
        api_documentation: Optional[TextIO],
        security_design_review: SDR,
    ) -> str:

        task = f"""
        # Introduction
        - You are a system security expert and hacker.

        # Tasks
        - Work on the following tasks.
        - Do not repeat this description in your response.
        - If data is not mentioned in the diagram apply the value 'MISSING'.

        ## Threats
        - Identify as many threats as possible
        - List the assets affected by the threat
        - Identify which components are affected by the threat and why
        - Explain in detail under what conditions the threat occurs and name an example
        - Mention which components are affected and why
        - Include the knowledge of OWASP Top 10
        - Assign a risks score from 1 (not critical) to 25 (critical)

        ### Default Threats
        - For databases consider missing backup mechanisms
        - For key material consider leakage and expiry scenarios
        - For authentication protocols consider missing validation of roles and permissions
        - For public entry points consider DDoS attacks

        ### OWASP Top 10
        - Broken Access Control
        - Cryptographic Failures
        - Injection
        - Security Misconfiguration
        - Vulnerable and Outdated Components
        - Identification and Authentication Failures
        - Software and Data Integrity Failures
        - Security Logging and Monitoring Failures
        - Server Side Request Forgery (SSRF)

        ## Mitigations
        - For each threat propose a set of mitigations

        ## Summary
        - Create a YAML object with the following attributes:
        ```
        threats:
            - threat: Some explanation
                components: Client, Server, Protocol
                condition: What technical conditions must be given
                score: 4
                mitigations:
                - mitigation 1
                - mitigation 2
            - threat: Some other explanation
                components: Client, Server, Protocol
                condition: What technical conditions must be given
                score: 12
                mitigations:
                - mitigation 3
                - mitigation 4
            - threat: Some other explanation
                components: Client, Server, Protocol
                condition: What technical conditions must be given
                score: 1
                mitigations:
                - mitigation 3
                - mitigation 4
            - threat: Some other explanation
                components: Client, Server, Protocol
                condition: What technical conditions must be given
                score: 1
                mitigations:
                - mitigation 3
        ```

        # System to Be Analyzed

        ```
        {security_design_review.to_yaml()}
        ```
        """

        messages = [
            ChatMessage(
                role="user",
                content=task,
            ),
        ]

        response = ""

        try:
            handle_event(RequestEvent(None))
            response = self.model.talk(messages, json=False)
            handle_event(ResponseEvent(None, message=response.message.content))

        except Exception as e:
            handle_event(ErrorEvent(None, error=e))

        return response

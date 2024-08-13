import json

from typing import Type, Callable, TextIO, Optional

from llama_index.core.llms import ChatMessage
from security_army_knife.agents.base_agent import (
    AgentEvent as Event,
    RequestEvent,
    ResponseEvent,
    ErrorEvent,
    AfterAnalysis,
    BeforeAnalysis,
    InformationEvent,
    CachedEvent,
)

from security_army_knife.agents.base_cve_agent import BaseCVEAgent
from security_army_knife.analysis.infrastructure_analysis import (
    InfrastructureAnalysis,
)
from security_army_knife.analysis.cve_analysis import CVEAnalysis
from security_army_knife.models.base_model import BaseModel


class InfrastructureAgent(BaseCVEAgent):

    dependencies: list[Type] = []

    def __init__(self, model: BaseModel, infrastructure_code: Optional[TextIO]):
        super().__init__(model=model)
        self.infrastructure_code = infrastructure_code

    def analyze(
        self,
        handle_event: Callable[[Event], None],
        analysis: CVEAnalysis,
    ) -> CVEAnalysis:

        if not self.infrastructure_code:
            return analysis

        if analysis.infrastructure_analysis:
            handle_event(CachedEvent())
            return analysis

        handle_event(BeforeAnalysis(message="infrastructure analysis starts"))

        infrastructure = self.infrastructure_code.read()

        task = f"""
        # Introduction
        - You are a security DevOps engineer responsible for infrastructure as code (IaC).

        # Tasks
        - Work on the following tasks.
        - Do not repeat this description in your response.

        ## Compo
        - Identify all infrastructure components with impact on security, like load balancers, VMs or any compute resource
        - Identify any configuration which has an impact on security, like open ports and which protocols are served
        - Explain why the component or the configuration matters for security
        - Identify the type of the component
        - Evaluate if the component is publicly accessible or not

        ## Summary
        - Create a JSON object with the following attributes:
        ```
        components:
        - name: component name
            - explanation: Why important for security?
            - public: true
            - type: Some Type
            - ports: 
                - 302
                - 8000
            - protocols: 
                - HTTP
                - MQTT
        - name: XY
            - explanation: Why important for security?
            - public: false
            - type: Some Type
            - ports:
                - 402
            - protocols:
                - HTTP
            - configurations:
                - Setting 1
                - Setting 2
        ```

        # Infrastructure To Be Analyzed

        ```
        {infrastructure}
        ```
        """

        messages = [
            ChatMessage(
                role="user",
                content=task,
            ),
        ]

        try:
            handle_event(RequestEvent())
            response = self.model.talk(messages, json=True)
            handle_event(ResponseEvent())

            json_object = json.loads(response.message.content)

            analysis.infrastructure_analysis = InfrastructureAnalysis.from_json(
                json_object
            )
            handle_event(
                InformationEvent(
                    message=f"{len(analysis.infrastructure_analysis.components)} security related components detected"
                )
            )

        except Exception as e:
            handle_event(ErrorEvent(error=e))

        handle_event(AfterAnalysis())

        return analysis

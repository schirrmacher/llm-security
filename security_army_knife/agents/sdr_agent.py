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


class SDRAgent(BaseAgent):

    dependencies: list[Type] = []

    def __init__(self, model: BaseModel):
        super().__init__(model=model)

    def analyze(
        self,
        handle_event: Callable[[Event], None],
        architecture_diagram: Optional[TextIO],
        api_documentation: Optional[TextIO],
    ) -> str:

        architecture = architecture_diagram.read()

        task = f"""
        # Introduction
        - You are a system security expert.

        # Tasks
        - Work on the following tasks.
        - Do not repeat this description in your response.
        - IF YOU CANNOT IDENTIFY DATA ASSIGN THE VALUE 'MISSING'!

        ## Analyze Data Flows
        - List all data flows
        - Highlight components accessible from the public internet which might be vulnerable to DoS attacks
        - Retrieve communication protocols, similar to HTTPS, MTLS, FTP etc.

        ## Public Entrypoints
        - Identify public entrypoints which are reachable from the internet

        ## Identify Environments
        - Identify the execution environment where a component is running
        - Categories: kubernetes, cloud function, customer, on-premise, on-edge (phone, laptop, embedded), other
        - Separate components by environments
        - Identify in which environment dataflows occur and add this information to the dataflow

        ## Assets
        - Identify data which is transmitted if possible.
        - Put those into a category called assets
        - Focus on critical assets which might be of value to customers or hackers

        ## Identify Persistence Layers
        - List all layers which are used for persistence
        - Identify which assets are persisted in the given persistence component
        - categorize the asset: pii (Personally identifiable information), secret, domain (business related data)

        ## Provisioning of Software Binaries
        - Identify software artifacts like binaries, SDKs, libraries, frameworks etc.
        - Categorize them: binary, SDK, library

        ## Identify Authentication and Authorization Protocols
        - Identify if authentication protocols are applied
        - List the protocols and which components apply them
        - Add the protocols to the associated dataflows

        ## Identify Algorithms
        - Identify algorithms used for authentication protocols or for protecting assets

        ## Threats
        - Identify risks for each dataflow and the associated asset
        - Include the knowledge of OWASP Top 10
        - Challenge how an attacker might get access to an asset by misusing technical conditions in the system
        - Assign a risks score from 1 (not critical) to 25 (critical)

        ### Default Threats
        - For databases consider missing backup mechanisms
        - For key material consider leakage and expiry
        - For authentication protocols consider missing validation of roles and permissions

        ### Threat Assumptions
        - Assume the implementation of TLS is secure

        ## Mitigations
        - For each threat propose a set of mitigations

        ## Summary
        - Create a YAML object with the following attributes:
        ```
        assets:
        - name: Cardholder Details
            category: pii|domain|secret

        public:
        - name: Entry point
            protocol: Some protocol
            authentication: Some authentication mechanism
            algorithms:
                - Some algorithms
            environment: Some environment

        dataflows:
        - source: Client
            destination: Some destination
            protocol: Some protocol
            authentication: Some authentication mechanism
            algorithms:
                - Some algorithms
            environment: Some environment
            assets:
            - Some asset

        persistence_layers:
        - name: Some database
            assets:
            - Some asset

        software_artifacts:
        - name: Some artifact
            category: Some category

        risks:
        - asset: Some affected asset
        threat: describe a potential threat
        mitigations: 
            - describe technical mitigations for the threat
        ```

        # Architecture Diagram To Be Analyzed

        ```
        {architecture}
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

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


class SDRAgent(BaseAgent):

    dependencies: list[Type] = []

    def __init__(self, model: BaseModel):
        super().__init__(model=model)

    def analyze(
        self,
        handle_event: Callable[[Event], None],
        architecture_diagram: Optional[TextIO],
        api_documentation: Optional[TextIO],
    ) -> SDR:

        architecture = architecture_diagram.read()

        task = f"""
        # Introduction
        - You are a system security expert.

        # Tasks
        - Work on the following tasks.
        - Do not repeat this description in your response.
        - If data is not mentioned in the diagram apply the value 'MISSING'.

        ## Analyze Data Flows
        - List all data flows
        - Retrieve communication protocols, like HTTPS, MTLS, FTP or any other protocol.
        - Identify which assets or data is transmitted.
        - Identify how the assets or data is protected by encryption, signatures or other security schemes.

        ## Entrypoints
        - Identify entrypoints which are reachable from the internet by external systems or users
        - Examples: load-balancers, API servers etc.

        ## Identify Environments
        - Identify the execution environment where a component is running
        - Identify in which environment the components of a dataflow are
        - Identify the environment for the source and destination to spot security boundaries
        - Consider components in the same container to be part of the same environment
        - Examples: kubernetes cluster, cloud function, device or any other
        - If no environment is mentioned use the 'MISSING' tag

        ## Assets
        - Identify data which is transmitted if possible.
        - Put those into a category called assets
        - Focus on critical assets which might be of value to customers or hackers

        ## Identify Persistence Layers
        - List all components which are used for persistence
        - Identify which assets are persisted in the given persistence component
        - Categorize the asset: pii (Personally identifiable information), secret (key material, passwords etc.), business (business related data)

        ## Provisioning of Software Artifacts
        - Identify software artifacts like binaries, SDKs, libraries, frameworks which are either provided to external sources or consumed from external sources
        - If no software artifacts are mentioned leave the result empty

        ## Identify Authentication and Authorization Schemes
        - Identify if authentication protocols are applied
        - If no authentication scheme is mentioned use the 'MISSING' tag
        - List the protocols and which components apply them
        - Add the protocols to the associated dataflows

        ## Identify Threat Actors
        - Identify what groups you consider as threat actors for this system
        - Explain why you consider these threat actors for the given system
        - Categories: employees, customers, nation-state, cybercriminals, competitors

        ## Summary
        - Create a JSON object with the following attributes:
        ```
        assets:
        - name: Cardholder Details
            category: pii|secret|business

        entrypoints:
        - name: Entry point name
            protocol: Some protocol
            authentication: Some authentication mechanism
            environment: Some environment

        persistence_layers:
        - name: Some database
            assets:
            - Some asset

        software_artifacts:
        - name: Some artifact
            category: Some category

        dataflows:
        - flow: Server -> Client
            protocol: Some protocol
            authentication: Some authentication mechanism
            environmentSrc: Server Environment
            environmentDst: Client Environment
            protection: Scheme for protecting asset
            assets:
                - Asset 1
                - Asset 2
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

        sdr: Optional[SDR] = None

        try:
            handle_event(RequestEvent(None))
            response = self.model.talk(messages, json=True)
            handle_event(ResponseEvent(None, message=response.message.content))

            json_object = json.loads(response.message.content)
            sdr = SDR.from_json(json_object)

        except Exception as e:
            handle_event(ErrorEvent(None, error=e))

        return sdr

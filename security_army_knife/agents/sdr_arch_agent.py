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
from security_army_knife.analysis.sdr_arch_analysis import SDRArchAnalysis
from security_army_knife.models.base_model import BaseModel


class SDRArchAgent(BaseAgent):

    dependencies: list[Type] = []

    def __init__(
        self, model: BaseModel, architecture_diagram: Optional[TextIO]
    ):
        super().__init__(model=model)
        self.architecture_diagram = architecture_diagram

    def analyze(
        self,
        handle_event: Callable[[Event], None],
        target: SDR,
    ) -> SDR:

        architecture = self.architecture_diagram.read()

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
        - Execution environments are platforms or technologies which embed a system component
        - Examples: kubernetes cluster, container service, cloud function, web browser, mobile device
        - Identify the environment for the source and destination of a dataflow to spot security boundaries
        - Consider components in the same container to be part of the same environment
        - If no environment is mentioned use the 'MISSING' tag

        ## Assets
        - Identify valuable business assets which are handled by the system
        - Focus on assets which might be of value to customers or hackers
        - Categorize assets accordingly
        - Also consider key material

        ## Software Artifacts
        - Identify all kinds of software artifacts so that we know what technologies are part of the system
        - Also consider hardware running software, like laptops, mobile phones, on-premise servers, payment terminals etc.
        - Examples: operating systems, SDKs, libraries, frameworks, databases, programming languages, vendors, platforms, hardware etc.

        ## Identify Persistence Layers
        - List all components which are used for persistence
        - Identify which assets are persisted in the given persistence component
        - Categorize the asset

        ## Identify Authentication and Authorization Schemes
        - Identify if authentication protocols or schemes are applied
        - If no authentication scheme is mentioned use the 'MISSING' tag
        - List the protocols and which components apply them
        - Add the protocols to the associated dataflows

        ## Summary
        - Create a JSON object with the following attributes:
        ```
        assets:
        - name: Some critical asset
            category: category of the asset
        - name: Another asset
            category: category of the asset

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
        - name: Some artifact
            category: Some category

        dataflows:
        - flow: Server -> Client
            protocol: Some protocol
            authentication: Some authentication mechanism
            environmentSrc: Server Environment
            environmentDst: Client Environment
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

        try:
            handle_event(RequestEvent(sdr=target))
            response = self.model.talk(messages, json=True)
            handle_event(ResponseEvent(sdr=target))

            json_object = json.loads(response.message.content)
            target.arch_analysis = SDRArchAnalysis.from_json(json_object)

            information = [
                InformationEvent(
                    sdr=target,
                    message=f"{len(target.arch_analysis.assets)} asset(s) identified",
                ),
                InformationEvent(
                    sdr=target,
                    message=f"{len(target.arch_analysis.software_artifacts)} software artifact(s) discovered",
                ),
                InformationEvent(
                    sdr=target,
                    message=f"{len(target.arch_analysis.entrypoints)} entrypoint(s) identified",
                ),
                InformationEvent(
                    sdr=target,
                    message=f"{len(target.arch_analysis.persistence_layers)} persistance layer(s) identified",
                ),
                InformationEvent(
                    sdr=target,
                    message=f"{len(target.arch_analysis.dataflows)} dataflow(s) analyzed",
                ),
            ]

            for i in information:
                handle_event(i)

        except Exception as e:
            handle_event(ErrorEvent(sdr=target, error=e))

        return target

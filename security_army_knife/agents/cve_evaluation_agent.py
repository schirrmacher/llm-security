import logging
import json
from typing import Callable, Type
from llama_index.core.llms import ChatMessage
from security_army_knife.agents.base_agent import (
    BaseAgent,
    AgentEvent as Event,
    BeforeAnalysis,
    AfterAnalysis,
    InformationEvent,
    CachedEvent,
    ErrorEvent,
)
from security_army_knife.analysis.cve_analysis import CVE, CVEAnalysis
from security_army_knife.agents.base_cve_agent import BaseCVEAgent
from security_army_knife.analysis.evaluation_analysis import EvaluationAnalysis

from security_army_knife.agents.api_spec_agent import APISpecAgent
from security_army_knife.agents.architecuture_agent import ArchitectureAgent
from security_army_knife.agents.cve_categorizer import CVECategorizerAgent
from security_army_knife.agents.infrastructure_agent import InfrastructureAgent
from security_army_knife.agents.source_code_agent import SourceCodeAgent


class CVEEvaluationAgent(BaseCVEAgent):

    dependencies: list[Type] = [
        InfrastructureAgent,
        CVECategorizerAgent,
        APISpecAgent,
        ArchitectureAgent,
        SourceCodeAgent,
    ]

    def __init__(self, model):
        super().__init__(model=model)
        self.logger = logging.getLogger("SecurityArmyKnife")

    def analyze(
        self, analysis: CVEAnalysis, handle_event: Callable[[Event], None]
    ) -> CVEAnalysis:
        for cve in analysis.cves:
            handle_event(BeforeAnalysis(cve))

            if cve.final_analysis:
                handle_event(CachedEvent(cve))
                continue

            try:

                summary, critical, threat_scenarios = self.evaluate_cve(
                    cve, analysis, handle_event
                )

                cve.final_analysis = EvaluationAnalysis(
                    critical=critical,
                    summary=summary,
                    threat_scenarios=threat_scenarios,
                )
                handle_event(
                    InformationEvent(
                        cve=cve,
                        message=(
                            "🔴 critical" if critical else "🟢 not critical"
                        ),
                    )
                )
                handle_event(
                    InformationEvent(
                        cve=cve,
                        message=f"{len(threat_scenarios)} attack scenarios provided",
                    )
                )
            except Exception as e:
                handle_event(ErrorEvent(cve=cve, error=e))

            handle_event(AfterAnalysis(cve))

        return analysis

    def evaluate_cve(
        self,
        cve: CVE,
        analysis: CVEAnalysis,
        handle_event: Callable[[Event], None],
    ):
        messages = [
            ChatMessage(
                role="system",
                content="You are a cybersecurity expert tasked with evaluating vulnerabilities.",
            ),
            ChatMessage(
                role="user",
                content=self.construct_prompt(cve=cve, analysis=analysis),
            ),
            ChatMessage(
                role="user",
                content="""Based on the provided information, please return the output in the following JSON format:
{
    "critical": true|false,
    "summary": "Detailed analysis and evaluation of the CVE.",
    "threat_scenarios": [
        "Scenario 1: Describe a potential attack scenario related to the CVE.",
        "Scenario 2: Describe another potential attack scenario related to the CVE."
    ]
}""",
            ),
        ]

        try:
            response = self.model.talk(messages, json=True)

            json_object = json.loads(response.message.content)

            summary = json_object.get("summary", "No summary provided.")
            critical = json_object.get("critical", False)
            threat_scenarios = json_object.get(
                "threat_scenarios", ["No scenarios provided."]
            )

            return summary, critical, threat_scenarios
        except Exception as e:
            handle_event(
                ErrorEvent(
                    cve=cve, error=f"Error in AI response processing: {e}"
                )
            )
            return (
                "Error generating summary",  # Summary
                False,  # Criticality
                ["Error generating threat scenarios"],  # Scenarios
            )

    def construct_prompt(self, cve: CVE, analysis: CVEAnalysis):
        task = f"""
            # Introduction
            - You are a cybersecurity expert specializing in evaluating software vulnerabilities.
            - The system is affected by a CVE described below.
            - Your task is to determine if the dedicated CVE is critical or not critical for our customers.

            # Tasks
            - Complete the following tasks without repeating this description in your response.
            - Ensure the summary clearly communicates the risk to stakeholders with varying technical expertise.
            - Focus on actionable insights and recommendations to guide decision-making.
            - Consider the design of the API specification, Code Analysis, Architecture Analysis and Infrastructure

            # Risk Assessment
            - Determine if the CVE is critical or not.
            - A critical CVE should meet one or more of the following criteria:
                - The CVE allows remote code execution with minimal effort.
                - The CVE can lead to a complete compromise of the system or highly sensitive data.
                - The vulnerability affects a wide range of systems and has a high potential impact.
                - The CVE can lead to a DoS attack with the current architecture.
            - Make sure that the attack conditions are met by the whole system.
            - If none of these criteria are met consider the CVE as non-critical.
                - Also CVE misusing local access to servers or operating systems are considered as non-critical, since we operate in the cloud (GCP)

            # Threat Scenarios
            - Highlight how an attacker might misuse technical conditions to exploit the vulnerability.
            - Consider the likelihood and of exploiting the vulnerability in the given environment.
            - Consider the impact of exploiting the vulnerability in the given environment.

            # System Overview
            - Take the following system information into consideration for evaluating the CVE criticality
            ```
            - Code Analysis: {cve.code_analysis.to_dict() if cve.code_analysis else 'No Code Analysis'}
            - Infrastructure:
            ```
            {analysis.infrastructure_analysis.to_dict()}
            ```

            ## System Details
            - Consider that we apply Java OpenJDK as runtime, ignore issues related to other runtimes
            - We operate in the Google Cloud (GCP)
            - Strictly compare if the technologies match the ones described in the CVE.
                - If not, consider the CVE as non-critical

            # CVE to be Analyzed
            - The following CVE is applied in the system described above
            - Make sure to consider the technical details for the evaluation
            ```
                - Name: {cve.name}
                - Description: {cve.description}
                - Java runtime required: {cve.category.java_runtime}
            ```

            ## Exploit Conditions
            - consider all exploit conditions below:
            ```
            {"-".join(cve.architecture_analysis.infrastructure_conditions) if cve.architecture_analysis else 'no exploit conditions given'}
            ```

            # Summary
            - Create a JSON object summarizing your findings with the following attributes:
            {{
            "critical": true|false,
            "summary": "Detailed analysis and evaluation of the CVE.",
            "threat_scenarios": [
            "Scenario 1: Description...",
            "Scenario 2: Description..."
            ]
            }}
            """

        return task

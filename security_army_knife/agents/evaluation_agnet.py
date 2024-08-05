import logging
import json
from typing import Callable, List
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
from security_army_knife.analysis.cve import CVE
from security_army_knife.analysis.evaluation_analysis import EvaluationAnalysis


class EvaluationAgent(BaseAgent):
    def __init__(self, model):
        super().__init__(model=model)
        self.logger = logging.getLogger("SecurityArmyKnife")

    def analyze(
        self, cve_list: List[CVE], handle_event: Callable[[Event], None]
    ) -> List[CVE]:
        for cve in cve_list:
            handle_event(BeforeAnalysis(cve))

            if cve.final_analysis:
                handle_event(CachedEvent(cve))
                continue

            # Log the details of the CVE and its analyses before evaluation
            self.logger.debug(f"CVE details: {cve}")

            try:
                # Evaluate and get score and summary using AI
                summary, critical, threat_scenarios = self.evaluate_cve(cve)

                # Store the results in the CVE object using EvaluationAnalysis
                cve.final_analysis = EvaluationAnalysis(
                    critical=critical,
                    summary=summary,
                    threat_scenarios=threat_scenarios,
                )

                handle_event(
                    InformationEvent(
                        cve,
                        f"Critical: {'Yes' if critical else 'No'}, Summary: {summary}, Threat Scenarios: {threat_scenarios}",
                    )
                )
            except Exception as e:
                self.logger.error(f"Unexpected error for {cve.name}: {e}")
                handle_event(ErrorEvent(cve, error=e))

            handle_event(AfterAnalysis(cve))

        return cve_list

    def evaluate_cve(self, cve: CVE):
        messages = [
            ChatMessage(
                role="system",
                content="You are a cybersecurity expert tasked with evaluating vulnerabilities.",
            ),
            ChatMessage(role="user", content=self.construct_prompt(cve)),
            ChatMessage(
                role="user",
                content="""Based on the provided information, please return the output in the following JSON format:
{
    "critical": "Yes | No",
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
            self.logger.info(f"Received response for {cve.name}")
            json_object = json.loads(response.message.content)

            summary = json_object.get("summary", "No summary provided.")
            critical = json_object.get("critical", "No")
            threat_scenarios = json_object.get(
                "threat_scenarios", ["No scenarios provided."]
            )

            return summary, critical, threat_scenarios
        except Exception as e:
            self.logger.error(f"Error in AI response processing: {e}")
            return (
                "Error generating summary",
                "Low",
                ["Error generating threat scenarios"],
            )

    def construct_prompt(self, cve: CVE):
        task = (
            f"# Introduction\n"
            f"- You are a cybersecurity expert specializing in evaluating software vulnerabilities.\n"
            f"- Your task is to determine if a CVE is critical, provide a comprehensive summary, and describe potential threat scenarios.\n"
            f"- Base your evaluation on the analyses conducted by different security agents and the given environment conditions.\n\n"
            f"# Tasks\n"
            f"- Complete the following tasks without repeating this description in your response.\n\n"
            f"## Evaluate CVE Details\n"
            f"- Consider the API Specification Analysis,Architecture Analysis.\n"
            f"- Analyze the potential impact of the vulnerability on confidentiality, integrity, and availability (CIA triad).\n\n"
            f"## Analyze Results from Security Agents\n"
            f"- Review the findings from the code analysis, API specification analysis, and architecture analysis.\n"
            f"- Evaluate how infrastructure conditions contribute to or mitigate the risk.\n\n"
            f"## Environment Considerations\n"
            f"- Consider that the system operates with strict network segmentation and firewall policies.\n"
            f"- Assume the environment is secured against local attacks.\n"
            f"- Identify how these environment conditions impact the exploitability of the vulnerability.\n\n"
            f"## Technology Relevance\n"
            f"- Assess whether the specific technology or system affected by the CVE is used in the environment.\n"
            f"- Consider the following:\n"
            f"  - Does the CVE target a technology stack, platform, or software version that is not present or utilized in this environment?\n"
            f"  - Are there compensating controls or alternative technologies that mitigate or negate the CVE's impact?\n"
            f"- If the CVE is irrelevant due to technology absence, classify it as non-critical.\n\n"
            f"## Risk Assessment\n"
            f"- Determine if the CVE is critical. A critical CVE should meet one or more of the following criteria:\n"
            f"  - The CVE allows remote code execution with minimal effort.\n"
            f"  - The CVE can lead to a complete compromise of the system or highly sensitive data.\n"
            f"  - The vulnerability affects a wide range of systems and has a high potential impact.\n"
            f"  - Existing security controls are insufficient to prevent exploitation.\n"
            f"- If none of these criteria are met, or if the technology is not relevant, consider the CVE as non-critical.\n\n"
            f"## Threat Scenarios\n"
            f"- Describe realistic threat scenarios and attack vectors relevant to the CVE.\n"
            f"- Highlight how an attacker might misuse technical conditions to exploit the vulnerability.\n"
            f"- Consider the likelihood and ease of exploiting the vulnerability in the given environment.\n\n"
            f"## Summary\n"
            f"- Create a JSON object summarizing your findings with the following attributes:\n"
            f"{{\n"
            f'"critical": "Yes | No",\n'
            f'"summary": "Detailed analysis and evaluation of the CVE.",\n'
            f'"threat_scenarios": [\n'
            f'"Scenario 1: Description...",\n'
            f'"Scenario 2: Description..."\n'
            f"]\n"
            f"}}\n\n"
            f"## Final Notes\n"
            f"- Ensure the summary clearly communicates the risk to stakeholders with varying technical expertise.\n"
            f"- Focus on actionable insights and recommendations to guide decision-making.\n"
            f"- Maintain a concise yet comprehensive explanation of the evaluation process.\n\n"
            f"# CVE Data for Analysis\n"
            f"- Name: {cve.name}\n"
            f"- Description: {cve.description}\n"
            f"- Category: {cve.category}\n"
            f"- Code Analysis: {cve.code_analysis if cve.code_analysis else 'No Code Analysis'}\n"
            f"- API Specification Analysis: {cve.api_spec_analysis.explanation if cve.api_spec_analysis else 'No API Spec Analysis'}\n"
            f"- Architecture Analysis: {cve.architecture_analysis if cve.architecture_analysis else 'No Architecture Analysis'}\n"
        )
        return task

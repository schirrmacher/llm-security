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
    ErrorEvent
)
from security_army_knife.analysis.cve import CVE
from security_army_knife.analysis.evaluation_analysis import EvaluationAnalysis

class EvaluationAgent(BaseAgent):
    def __init__(self, model):
        super().__init__(model=model)
        self.logger = logging.getLogger("SecurityArmyKnife")

    def analyze(self, cve_list: List[CVE], handle_event: Callable[[Event], None]) -> List[CVE]:
        for cve in cve_list:
            self.logger.info(f"Analyzing {cve.name} in EvaluationAgent...")
            handle_event(BeforeAnalysis(cve))

            if cve.final_analysis:
                handle_event(CachedEvent(cve))
                continue

            # Log the details of the CVE and its analyses before evaluation
            self.logger.debug(f"CVE details: {cve}")

            try:
                # Evaluate and get score and summary using AI
                summary, severity, threat_scenarios = self.evaluate_cve(cve)

                # Store the results in the CVE object using EvaluationAnalysis
                cve.final_analysis = EvaluationAnalysis(severity=severity, summary=summary, threat_scenarios=threat_scenarios)
                
                # Output the results
                self.output_results(cve)

                handle_event(InformationEvent(cve, f"Severity: {severity}, Summary: {summary}, Threat Scenarios: {threat_scenarios}"))
                self.logger.info(f"Final Analysis: {cve.final_analysis}")
            except Exception as e:
                self.logger.error(f"Unexpected error for {cve.name}: {e}")
                handle_event(ErrorEvent(cve, error=e))
                
            handle_event(AfterAnalysis(cve))

        return cve_list

    def evaluate_cve(self, cve: CVE):
        # Use the AI model to generate summary and severity
        messages = [
            ChatMessage(
                role="system",
                content="You are a cybersecurity expert tasked with evaluating vulnerabilities."
            ),
            ChatMessage(
                role="user",
                content=self.construct_prompt(cve)
            ),
            ChatMessage(
                role="user",
                content="""Based on the provided information, please return the output in the following JSON format:
{
    "severity": "High | Medium | Low",
    "summary": "Detailed analysis and evaluation of the CVE.",
    "threat_scenarios": [
        "Scenario 1: Describe a potential attack scenario related to the CVE.",
        "Scenario 2: Describe another potential attack scenario related to the CVE."
    ]
}"""
            )
        ]

        try:
            response = self.model.talk(messages, json=True)
            self.logger.info(f"Received response for {cve.name}")
            json_object = json.loads(response.message.content)

            summary = json_object.get("summary", "No summary provided.")
            severity = json_object.get("severity", "Low")
            threat_scenarios = json_object.get("threat_scenarios", ["No scenarios provided."])

            return summary, severity, threat_scenarios
        except Exception as e:
            self.logger.error(f"Error in AI response processing: {e}")
            return "Error generating summary", "Low", ["Error generating threat scenarios"]

    def construct_prompt(self, cve: CVE):
        task = (
            f"# Introduction\n"
            f"- You are a cybersecurity expert specializing in evaluating software vulnerabilities.\n"
            f"- Your task is to assess the severity and provide a comprehensive summary of each CVE.\n"
            f"- Base your evaluation on the analyses conducted by different security agents and the given environment conditions.\n\n"

            f"# Tasks\n"
            f"- Complete the following tasks without repeating this description in your response.\n\n"

            f"## Evaluate CVE Details\n"
            f"- Consider the CVE's name, description, and category.\n"
            f"- Analyze the potential impact of the vulnerability on confidentiality, integrity, and availability.\n\n"

            f"## Analyze Results from Security Agents\n"
            f"- Review the findings from the code analysis, API specification analysis, and architecture analysis.\n"
            f"- Identify if the API facilitates the vulnerability or mitigates it.\n"
            f"- Evaluate infrastructure conditions to determine how they contribute to or mitigate the risk.\n\n"

            f"## Environment Considerations\n"
            f"- Consider that the system operates with strict network segmentation and firewall policies.\n"
            f"- Assume the environment is secured against local attacks.\n"
            f"- Identify how these environment conditions impact the exploitability of the vulnerability.\n\n"

            f"## Risk Assessment\n"
            f"- Assign a severity level (High, Medium, Low) based on the aggregated information.\n"
            f"- Consider the OWASP Top 10 vulnerabilities and other common security threats in your assessment.\n"
            f"- Determine how the CVE might be exploited in the current environment.\n\n"

            f"## Threat Scenarios\n"
            f"- Describe potential threat scenarios and attack vectors relevant to the CVE.\n"
            f"- Highlight how an attacker might misuse technical conditions to exploit the vulnerability.\n\n"

            f"## Summary\n"
            f"- Create a JSON object summarizing your findings with the following attributes:\n"
            f"{{\n"
            f"\"severity\": \"High | Medium | Low\",\n"
            f"\"summary\": \"Detailed analysis and evaluation of the CVE.\",\n"
            f"\"threat_scenarios\": [\n"
            f"\"Scenario 1: Description...\",\n"
            f"\"Scenario 2: Description...\"\n"
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
            f"- API Specification Analysis: {cve.api_spec_analysis if cve.api_spec_analysis else 'No API Spec Analysis'}\n"
            f"- Architecture Analysis: {cve.architecture_analysis if cve.architecture_analysis else 'No Architecture Analysis'}\n"
        )
        return task
    
    def output_results(self, cve: CVE):
        """Outputs the results for the given CVE."""
        print(f"Analysis for {cve.name}:")
        print(f"  Severity: {cve.final_analysis.severity}")
        print(f"  Summary: {cve.final_analysis.summary}")
        print(f"  Threat Scenarios: {', '.join(cve.final_analysis.threat_scenarios)}\n")

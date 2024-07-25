import re
import json

from pathlib import Path
from typing import Callable, Type

from llama_index.core.llms import ChatMessage
from security_army_knife.agents.base_agent import (
    BaseAgent,
    AgentEvent as Event,
    InformationEvent,
    CachedEvent,
    BeforeAnalysis,
    AfterAnalysis,
    ErrorEvent,
)
from security_army_knife.base_model import BaseModel

from security_army_knife.agents.cve_categorizer import CVECategorizerAgent
from security_army_knife.analysis.cve import CVE
from security_army_knife.analysis.code_analysis import CodeAnalysis


class SourceCodeAgent(BaseAgent):

    dependencies: list[Type] = [CVECategorizerAgent]

    def __init__(self, model: BaseModel, source_code_path: str):
        super().__init__(model=model)
        self.source_code_path = source_code_path

    @staticmethod
    def _list_files_recursive(folder_path: str) -> list[str]:
        path = Path(folder_path)
        return [str(file) for file in path.rglob("*") if file.is_file()]

    @staticmethod
    def _apply_regexes_to_files(files: list[str], regexes: list[str]) -> bool:
        matching_files = []
        for file_path in files:
            with open(
                file_path, "r", encoding="utf-8", errors="ignore"
            ) as file:
                content = file.read()
                if any(re.compile(regex).search(content) for regex in regexes):
                    matching_files.append(file_path)
        return matching_files

    def analyze(
        self,
        cve_list: list[CVE],
        handle_event: Callable[[Event], None],
    ) -> list[CVE]:

        all_file_paths = self._list_files_recursive(self.source_code_path)

        for cve in cve_list:

            handle_event(BeforeAnalysis(cve))

            if cve.code_analysis:
                handle_event(CachedEvent(cve))
                continue

            logging.info(f"{self.__class__.__name__}: analyzing {cve.name}")

            task = f"For the following CVE, how can you detect it in code? Create a regular expression string, only if applicable: {cve.to_json()}"
            formatting = "Format the result as JSON and add the attribute 'code_queries' as a string list to this object. Leave the list empty if not applicable."

            messages = [
                ChatMessage(
                    role="system",
                    content="You are security code reviewer.",
                ),
                ChatMessage(
                    role="user",
                    content=task,
                ),
                ChatMessage(
                    role="user",
                    content=formatting,
                ),
            ]

            try:
                response = self.model.talk(messages, json=True)

                json_object = json.loads(response.message.content)

                queries = json_object.get("queries", [])
                cve.code_analysis = CodeAnalysis(queries=queries)

                handle_event(InformationEvent(cve, f"queries: {queries}"))

                matches = self._apply_regexes_to_files(
                    files=all_file_paths, regexes=cve.code_analysis.queries
                )

                cve.code_analysis.affected_files = matches

                handle_event(InformationEvent(cve, f"affected: {matches}"))

            except Exception as e:
                cve.code_analysis.queries = []
                handle_event(ErrorEvent(cve, error=e))

            handle_event(AfterAnalysis(cve))

        return cve_list

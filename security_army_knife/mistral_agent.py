import os
from llama_index.core.llms import ChatMessage, ChatResponse
from llama_index.llms.mistralai import MistralAI


class MistralAgent:
    def __init__(self, api_key_env_var="MISTRALAI_API_KEY"):
        self.api_key = os.getenv(api_key_env_var)
        if not self.api_key:
            raise ValueError(
                f"Please set the Mistral API key environment variable:\n\nexport {api_key_env_var}=<API_KEY>\n"
            )
        self.llm = MistralAI(
            model="mistral-large-latest",
            api_key=self.api_key,
            max_tokens=4096 * 32,
        )

    def talk(self, messages: ChatMessage, json=False) -> ChatResponse:
        if json:
            response = self.llm.chat(
                messages, response_format={"type": "json_object"}
            )
        else:
            response = self.llm.chat(messages)
        return response

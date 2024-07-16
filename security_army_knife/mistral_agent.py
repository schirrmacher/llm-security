import os
from llama_index.llms.mistralai import MistralAI


class MistralAgent:
    def __init__(self, api_key_env_var="MISTRALAI_API_KEY"):
        self.api_key = os.getenv(api_key_env_var)
        if not self.api_key:
            raise ValueError(
                f"Please set the Mistral API key environment variable:\n\nexport {api_key_env_var}=<API_KEY>\n"
            )
        self.llm = MistralAI(api_key=self.api_key)

    def talk(self, prompt: str):
        response = self.llm.complete(prompt)
        return str(response)

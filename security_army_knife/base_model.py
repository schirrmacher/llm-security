import os
from abc import ABC, abstractmethod
from llama_index.core.llms import ChatMessage, ChatResponse


class BaseModel(ABC):
    def __init__(self, api_key_env_var: str, model_name: str, max_tokens: int):
        self.api_key = os.getenv(api_key_env_var)
        if not self.api_key:
            raise ValueError(
                f"Please set the API key environment variable:\n\nexport {api_key_env_var}=<API_KEY>\n"
            )
        self.model_name = model_name
        self.max_tokens = max_tokens
        self.llm = self.create_llm()

    @abstractmethod
    def create_llm(self):
        pass

    @abstractmethod
    def talk(self, messages: ChatMessage, json: bool = False) -> ChatResponse:
        pass

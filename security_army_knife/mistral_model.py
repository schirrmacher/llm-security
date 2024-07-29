import logging

from llama_index.core.llms import ChatMessage, ChatResponse
from llama_index.llms.mistralai import MistralAI

from security_army_knife.base_model import BaseModel


class MistralModel(BaseModel):
    def __init__(self, api_key_env_var="MISTRALAI_API_KEY"):
        super().__init__(
            api_key_env_var,
            model_name="mistral-large-latest",
            max_tokens=4096 * 32,
        )

    def create_llm(self):
        return MistralAI(
            model=self.model_name,
            api_key=self.api_key,
            max_tokens=self.max_tokens,
        )

    def talk(self, messages: ChatMessage, json: bool = False) -> ChatResponse:
        # Disable logging for model requests, maybe there is a better solution
        # but this works
        previous_level = logging.getLogger().getEffectiveLevel()
        logger = logging.getLogger("SecurityArmyKnife")
        logging.disable(logging.CRITICAL)
        if json:
            response = self.llm.chat(
                messages, response_format={"type": "json_object"}
            )
        else:
            response = self.llm.chat(messages)

        logging.disable(logging.NOTSET)
        return response

import logging

from typing import List

from mistralai import Mistral
from llama_index.core.llms import ChatMessage, ChatResponse

from security_army_knife.models.base_model import BaseModel


def map_chat_messages_to_dicts(chat_messages: List[ChatMessage]) -> List[dict]:
    return [
        {"role": message.role.name.lower(), "content": message.content}
        for message in chat_messages
    ]


class MessageContent:
    def __init__(self, content: str):
        self.content = content


class MessageWrapper:
    def __init__(self, message: MessageContent):
        self.message = message


class MistralModel(BaseModel):
    def __init__(self, api_key_env_var="MISTRALAI_API_KEY"):
        super().__init__(
            api_key_env_var,
            model_name="mistral-large-latest",
            max_tokens=4096 * 32,
        )

    def create_llm(self):
        return Mistral(
            api_key=self.api_key,
        )

    def talk(self, messages: ChatMessage, json: bool = False) -> ChatResponse:

        # Disable logging for model requests, maybe there is a better solution
        # but this works
        logging.disable(logging.CRITICAL)
        if json:
            response = self.llm.chat.complete(
                model=self.model_name,
                temperature=0.0,
                messages=map_chat_messages_to_dicts(messages),
                response_format={"type": "json_object"},
            )
        else:
            response = self.llm.chat.complete(
                model=self.model_name,
                messages=map_chat_messages_to_dicts(messages),
            )

        message_content = MessageContent(
            content=response.choices[0].message.content
        )
        message_wrapper = MessageWrapper(message=message_content)

        logging.disable(logging.NOTSET)
        return message_wrapper

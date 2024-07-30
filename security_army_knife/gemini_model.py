from llama_index.core.llms import ChatMessage, ChatResponse
from llama_index.llms.gemini import Gemini

from security_army_knife.base_model import BaseModel


class GeminiModel(BaseModel):
    def __init__(self, api_key_env_var="GOOGLE_API_KEY"):
        super().__init__(
            api_key_env_var,
            model_name="models/gemini-1.5-pro",
            max_tokens=4096 * 32,
        )

    def create_llm(self):
        safety = [
            {
                "category": "HARM_CATEGORY_DANGEROUS",
                "threshold": "BLOCK_NONE",
            },
            {
                "category": "HARM_CATEGORY_HARASSMENT",
                "threshold": "BLOCK_NONE",
            },
            {
                "category": "HARM_CATEGORY_HATE_SPEECH",
                "threshold": "BLOCK_NONE",
            },
            {
                "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                "threshold": "BLOCK_NONE",
            },
            {
                "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                "threshold": "BLOCK_NONE",
            },
        ]
        return Gemini(
            model=self.model_name,
            api_key=self.api_key,
            generation_config={"response_mime_type": "application/json"},
            safety_settings=safety,
        )

    def talk(self, messages: ChatMessage, json: bool = True) -> ChatResponse:
        response = self.llm.chat(messages)
        return response

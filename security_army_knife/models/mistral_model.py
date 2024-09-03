import logging
import requests
import subprocess

from typing import List, Optional

from mistralai import Mistral

from llama_index.core.llms import ChatMessage, ChatResponse

from security_army_knife.models.base_model import BaseModel

LOCATION = "europe-west4"
MODEL = "mistral-large"
MODEL_VERSION = "latest"

PROJECT_ID = "pt-dev-security"
ENDPOINT = f"https://{LOCATION}-aiplatform.googleapis.com"
SELECTED_MODEL_VERSION = (
    "" if MODEL_VERSION == "latest" else f"@{MODEL_VERSION}"
)


def map_chat_messages_to_dicts(chat_messages: List[ChatMessage]) -> List[dict]:
    return [
        {"role": message.role.name.lower(), "content": message.content}
        for message in chat_messages
    ]


def read_file_as_string(file_path) -> Optional[str]:
    try:
        with open(file_path, "r") as file:
            content = file.read()
        return content
    except FileNotFoundError:
        logging.error(f"The file {file_path} does not exist.")
        return None
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return None


class MessageContent:
    def __init__(self, content: str):
        self.content = content


class MessageWrapper:
    def __init__(self, message: MessageContent):
        self.message = message


class MistralModel(BaseModel):
    def __init__(self, access_token_var="GOOGLE_APPLICATION_CREDENTIALS"):
        self.access_token_var = access_token_var

    def create_llm(self):
        return Mistral(
            api_key=self.api_key,
        )

    def talk(self, messages: ChatMessage, json: bool = False) -> ChatResponse:

        access_token = None

        if not access_token:
            process = subprocess.Popen(
                "gcloud auth print-access-token",
                stdout=subprocess.PIPE,
                shell=True,
            )
            (access_token_bytes, err) = process.communicate()
            access_token = access_token_bytes.decode("utf-8").strip()

        # Define query headers
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        url = f"{ENDPOINT}/v1/projects/{PROJECT_ID}/locations/{LOCATION}/publishers/mistralai/models/{MODEL}{SELECTED_MODEL_VERSION}:rawPredict"
        data = {
            "model": MODEL,
            "messages": map_chat_messages_to_dicts(messages),
            "stream": False,
            "response_format": {"type": "json_object"},
        }

        response = requests.post(url, headers=headers, json=data)

        if response.status_code == 200:
            try:
                response_dict = response.json()
                message_content = MessageContent(
                    content=response_dict["choices"][0]["message"]["content"]
                )
                message_wrapper = MessageWrapper(message=message_content)
                return message_wrapper
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding JSON: {e}")
        else:
            logging.error(
                f"Request failed with status code: {response.status_code}"
            )

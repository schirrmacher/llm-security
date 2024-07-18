from security_army_knife.base_model import BaseModel


class BaseAgent:
    def __init__(self, model: BaseModel):
        self.model = model

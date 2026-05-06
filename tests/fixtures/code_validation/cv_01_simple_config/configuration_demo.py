from transformers import PretrainedConfig


class DemoConfig(PretrainedConfig):
    model_type = "demo"

    def __init__(self, hidden_size=128, **kwargs):
        super().__init__(**kwargs)
        self.hidden_size = hidden_size

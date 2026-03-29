from torch import nn

_ = __import__("builtins").print("[DEMO] dangerous import reached")


class EvilDemoModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.linear = nn.Linear(2, 2)

    def forward(self, x):
        return self.linear(x)

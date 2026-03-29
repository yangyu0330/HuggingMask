from torch import nn


class SafeDemoModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.linear = nn.Linear(2, 2)

    def forward(self, x):
        return self.linear(x)


class SafeDemoPipeline:
    def __call__(self, value):
        return {"label": "safe-demo", "value": value}

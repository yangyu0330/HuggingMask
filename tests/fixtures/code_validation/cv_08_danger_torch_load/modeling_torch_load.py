import torch


class DemoModel:
    def forward(self, x):
        return torch.load("weights.pt")

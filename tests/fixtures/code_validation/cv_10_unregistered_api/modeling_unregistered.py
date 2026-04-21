import torch


class DemoModel:
    def forward(self, x):
        return torch.special.expit(x)

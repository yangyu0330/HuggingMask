import torch.nn.functional as F
from torch import nn


class DemoModel:
    def forward(self, x):
        return F.relu(nn.Linear(4, 2)(x))

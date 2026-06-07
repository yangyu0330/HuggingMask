from __future__ import annotations

import re
from enum import Enum
from pathlib import PurePosixPath

from analyzer.classifier import normalize_repo_path


class PickleRole(str, Enum):
    DEPLOYABLE_WEIGHT = "DEPLOYABLE_WEIGHT"
    AUXILIARY_TRAINING = "AUXILIARY_TRAINING"
    GENERIC_PICKLE = "GENERIC_PICKLE"
    UNSUPPORTED_CHECKPOINT = "UNSUPPORTED_CHECKPOINT"


CHECKPOINT_EXTENSIONS = {".pth", ".ckpt"}

DEPLOYABLE_WEIGHT_NAMES = {
    "pytorch_model.bin",
    "pytorch_model.pt",
    "adapter_model.bin",
    "adapter_model.pt",
    "diffusion_pytorch_model.bin",
}

AUXILIARY_TRAINING_NAMES = {
    "training_args.bin",
    "trainer_state.bin",
    "trainer_state.pkl",
    "trainer_state.pt",
    "optimizer.bin",
    "optimizer.pkl",
    "optimizer.pt",
    "scheduler.bin",
    "scheduler.pkl",
    "scheduler.pt",
    "scaler.bin",
    "scaler.pkl",
    "scaler.pt",
}

DEPLOYABLE_WEIGHT_PATTERNS = (
    re.compile(r"^pytorch_model-\d{5}-of-\d{5}\.(bin|pt|pkl)$"),
    re.compile(r"^adapter_model-\d{5}-of-\d{5}\.(bin|pt|pkl)$"),
    re.compile(r"^diffusion_pytorch_model-\d{5}-of-\d{5}\.(bin|pt|pkl)$"),
)

AUXILIARY_TRAINING_PATTERNS = (
    re.compile(r"^rng_state(_\d+)?\.(bin|pt|pkl)$"),
    re.compile(r"^training_args(_\d+)?\.(bin|pt|pkl)$"),
)


def classify_pickle_role(repo_path: str, file_name: str | None = None) -> PickleRole:
    normalized_path = normalize_repo_path(repo_path).lower()
    path = PurePosixPath(normalized_path)
    name = (file_name or path.name).lower()
    suffix = PurePosixPath(name).suffix

    if suffix in CHECKPOINT_EXTENSIONS:
        return PickleRole.UNSUPPORTED_CHECKPOINT

    if name in AUXILIARY_TRAINING_NAMES:
        return PickleRole.AUXILIARY_TRAINING

    if any(pattern.match(name) for pattern in AUXILIARY_TRAINING_PATTERNS):
        return PickleRole.AUXILIARY_TRAINING

    if name in DEPLOYABLE_WEIGHT_NAMES:
        return PickleRole.DEPLOYABLE_WEIGHT

    if any(pattern.match(name) for pattern in DEPLOYABLE_WEIGHT_PATTERNS):
        return PickleRole.DEPLOYABLE_WEIGHT

    if (
        any(part.startswith("checkpoint-") for part in path.parts)
        and name in AUXILIARY_TRAINING_NAMES
    ):
        return PickleRole.AUXILIARY_TRAINING

    return PickleRole.GENERIC_PICKLE

"""
초기 화이트리스트 시드 — PyTorch / Transformers / NumPy 핵심 추론 API

프록시 최초 배포 시 DB에 로드된다 (source=INITIAL).
"""

SEED_TORCH_NN = [
    "torch.nn.Module", "torch.nn.Linear",
    "torch.nn.Conv1d", "torch.nn.Conv2d", "torch.nn.Conv3d", "torch.nn.ConvTranspose2d",
    "torch.nn.BatchNorm1d", "torch.nn.BatchNorm2d", "torch.nn.LayerNorm",
    "torch.nn.GroupNorm", "torch.nn.RMSNorm",
    "torch.nn.Dropout", "torch.nn.Embedding",
    "torch.nn.LSTM", "torch.nn.GRU", "torch.nn.RNN",
    "torch.nn.Transformer", "torch.nn.TransformerEncoder", "torch.nn.TransformerDecoder",
    "torch.nn.TransformerEncoderLayer", "torch.nn.TransformerDecoderLayer",
    "torch.nn.MultiheadAttention",
    "torch.nn.Sequential", "torch.nn.ModuleList", "torch.nn.ModuleDict",
    "torch.nn.ParameterList", "torch.nn.Parameter",
    "torch.nn.Softmax", "torch.nn.LogSoftmax",
    "torch.nn.CrossEntropyLoss", "torch.nn.MSELoss",
    "torch.nn.BCELoss", "torch.nn.BCEWithLogitsLoss",
    "torch.nn.ReLU", "torch.nn.GELU", "torch.nn.SiLU", "torch.nn.Tanh", "torch.nn.Sigmoid",
    "torch.nn.Flatten", "torch.nn.Unflatten",
    "torch.nn.MaxPool2d", "torch.nn.AvgPool2d", "torch.nn.AdaptiveAvgPool2d",
]

SEED_TORCH_FUNCTIONAL = [
    "torch.nn.functional.relu", "torch.nn.functional.gelu", "torch.nn.functional.silu",
    "torch.nn.functional.sigmoid", "torch.nn.functional.tanh",
    "torch.nn.functional.softmax", "torch.nn.functional.log_softmax",
    "torch.nn.functional.cross_entropy", "torch.nn.functional.mse_loss",
    "torch.nn.functional.linear", "torch.nn.functional.conv2d",
    "torch.nn.functional.dropout", "torch.nn.functional.layer_norm",
    "torch.nn.functional.batch_norm", "torch.nn.functional.embedding",
    "torch.nn.functional.interpolate", "torch.nn.functional.pad",
    "torch.nn.functional.scaled_dot_product_attention",
    "torch.nn.functional.multi_head_attention_forward",
    "torch.nn.functional.normalize",
]

SEED_TORCH_OPS = [
    "torch.tensor", "torch.zeros", "torch.ones", "torch.randn",
    "torch.arange", "torch.linspace",
    "torch.cat", "torch.stack", "torch.squeeze", "torch.unsqueeze",
    "torch.reshape", "torch.permute", "torch.transpose",
    "torch.matmul", "torch.bmm", "torch.einsum",
    "torch.where", "torch.clamp",
    "torch.abs", "torch.sqrt", "torch.exp", "torch.log",
    "torch.sum", "torch.mean", "torch.max", "torch.min",
    "torch.argmax", "torch.argmin", "torch.topk", "torch.sort",
    "torch.no_grad", "torch.inference_mode",
    "torch.is_tensor", "torch.as_tensor", "torch.from_numpy",
    "torch.empty", "torch.full",
    "torch.triu", "torch.tril", "torch.masked_fill",
    "torch.compile",
]

SEED_TRANSFORMERS = [
    "transformers.AutoModel",
    "transformers.AutoModelForCausalLM",
    "transformers.AutoModelForSequenceClassification",
    "transformers.AutoModelForTokenClassification",
    "transformers.AutoModelForQuestionAnswering",
    "transformers.AutoModelForSeq2SeqLM",
    "transformers.AutoTokenizer",
    "transformers.AutoConfig",
    "transformers.AutoProcessor",
    "transformers.AutoFeatureExtractor",
    "transformers.PreTrainedModel",
    "transformers.PretrainedConfig",
    "transformers.PreTrainedTokenizer",
    "transformers.PreTrainedTokenizerFast",
    "transformers.GenerationConfig", "transformers.GenerationMixin",
    "transformers.TextStreamer", "transformers.pipeline",
    "transformers.BitsAndBytesConfig",
]

SEED_NUMPY = [
    "numpy.array", "numpy.zeros", "numpy.ones",
    "numpy.arange", "numpy.linspace",
    "numpy.reshape", "numpy.concatenate", "numpy.stack",
    "numpy.squeeze", "numpy.expand_dims", "numpy.transpose",
    "numpy.mean", "numpy.std", "numpy.sum", "numpy.max", "numpy.min",
    "numpy.argmax", "numpy.argmin", "numpy.clip",
    "numpy.float32", "numpy.float16", "numpy.int64",
]

ALL_SEED_APIS: list[str] = (
    SEED_TORCH_NN + SEED_TORCH_FUNCTIONAL + SEED_TORCH_OPS
    + SEED_TRANSFORMERS + SEED_NUMPY
)


def get_seed_with_namespaces() -> list[tuple[str, str]]:
    """(api_path, namespace) 튜플 리스트"""
    result = []
    for api in ALL_SEED_APIS:
        parts = api.rsplit(".", 1)
        ns = parts[0] if len(parts) > 1 else api
        result.append((api, ns))
    return result

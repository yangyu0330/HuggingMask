"""
AI 모델 공급망 보안 프록시 — config.json / tokenizer 검증 데모
캡스톤디자인 프로젝트

실행: python config_validator_demo.py
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from pathlib import Path

# ────────────────────────────────────────────────
# 색상 출력
# ────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def red(s):    return f"{C.RED}{s}{C.RESET}"
def green(s):  return f"{C.GREEN}{s}{C.RESET}"
def yellow(s): return f"{C.YELLOW}{s}{C.RESET}"
def blue(s):   return f"{C.BLUE}{s}{C.RESET}"
def cyan(s):   return f"{C.CYAN}{s}{C.RESET}"
def bold(s):   return f"{C.BOLD}{s}{C.RESET}"
def dim(s):    return f"{C.DIM}{s}{C.RESET}"


# ────────────────────────────────────────────────
# 화이트리스트 정의
# ────────────────────────────────────────────────
# PreTrainedConfig 공식 문서 + 주요 모델 계열 기반
# 출처: huggingface.co/docs/transformers/main_classes/configuration

ALLOWED_FIELDS = {

    # ── PreTrainedConfig 공통 (모든 모델) ──────────
    "model_type":                       str,
    "architectures":                    list,
    "_name_or_path":                    str,   # 값 내용 추가 검사
    "transformers_version":             str,
    "torch_dtype":                      str,
    "tokenizer_class":                  str,
    "is_encoder_decoder":               bool,
    "is_decoder":                       bool,
    "use_cache":                        bool,
    "use_return_dict":                  bool,
    "output_hidden_states":             bool,
    "output_attentions":                bool,
    "tie_word_embeddings":              bool,
    "add_cross_attention":              bool,
    "chunk_size_feed_forward":          int,
    "num_labels":                       int,
    "id2label":                         dict,
    "label2id":                         dict,
    "finetuning_task":                  (str, type(None)),
    "problem_type":                     (str, type(None)),
    "keys_to_ignore_at_inference":      list,

    # ── 토큰 ID (공통) ─────────────────────────────
    "pad_token_id":                     (int, type(None)),
    "bos_token_id":                     (int, type(None)),
    "eos_token_id":                     (int, list, type(None)),
    "sep_token_id":                     (int, type(None)),
    "cls_token_id":                     (int, type(None)),
    "unk_token_id":                     (int, type(None)),
    "mask_token_id":                    (int, type(None)),
    "decoder_start_token_id":           (int, type(None)),
    "forced_bos_token_id":              (int, type(None)),
    "forced_eos_token_id":              (int, list, type(None)),

    # ── 생성(generation) 파라미터 ─────────────────
    "max_length":                       int,
    "min_length":                       int,
    "max_new_tokens":                   (int, type(None)),
    "do_sample":                        bool,
    "num_beams":                        int,
    "num_beam_groups":                  int,
    "temperature":                      float,
    "top_k":                            int,
    "top_p":                            float,
    "typical_p":                        float,
    "repetition_penalty":               float,
    "length_penalty":                   float,
    "no_repeat_ngram_size":             int,
    "early_stopping":                   (bool, str),
    "diversity_penalty":                float,
    "remove_invalid_values":            bool,
    "exponential_decay_length_penalty": (list, type(None)),

    # ── BERT / RoBERTa / DistilBERT / ALBERT ──────
    "hidden_size":                      int,
    "num_hidden_layers":                int,
    "num_attention_heads":              int,
    "intermediate_size":                int,
    "hidden_act":                       str,
    "hidden_dropout_prob":              float,
    "attention_probs_dropout_prob":     float,
    "max_position_embeddings":          int,
    "type_vocab_size":                  int,
    "initializer_range":                float,
    "layer_norm_eps":                   float,
    "vocab_size":                       int,
    "position_embedding_type":          str,
    "classifier_dropout":               (float, type(None)),
    "cross_attention_hidden_size":      (int, type(None)),
    "add_pooling_layer":                bool,
    "embedding_size":                   int,        # ALBERT
    "inner_group_num":                  int,        # ALBERT
    "num_hidden_groups":                int,        # ALBERT
    "net_structure_type":               int,        # ALBERT
    "gap_size":                         int,        # ALBERT
    "num_memory_blocks":                int,        # ALBERT

    # ── GPT-2 / GPT-J / GPT-Neo ───────────────────
    "n_embd":                           int,
    "n_layer":                          int,
    "n_head":                           int,
    "n_positions":                      int,
    "n_ctx":                            int,
    "n_inner":                          (int, type(None)),
    "activation_function":              str,
    "resid_pdrop":                      float,
    "embd_pdrop":                       float,
    "attn_pdrop":                       float,
    "layer_norm_epsilon":               float,
    "scale_attn_weights":               bool,
    "scale_attn_by_inverse_layer_idx":  bool,
    "reorder_and_upcast_attn":          bool,
    "rotary_dim":                       (int, type(None)),   # GPT-J
    "rotary_pct":                       float,               # GPT-NeoX
    "attention_layers":                 list,                # GPT-Neo

    # ── LLaMA / Mistral / Qwen / Gemma ───────────
    "num_key_value_heads":              int,
    "rms_norm_eps":                     float,
    "rope_theta":                       float,
    "rope_scaling":                     (dict, type(None)),
    "attention_dropout":                float,
    "attention_bias":                   bool,
    "mlp_bias":                         bool,
    "sliding_window":                   (int, type(None)),
    "max_window_layers":                (int, type(None)),
    "pretraining_tp":                   int,                 # LLaMA
    "head_dim":                         (int, type(None)),   # Gemma
    "query_pre_attn_scalar":            (int, type(None)),   # Gemma2

    # ── T5 / BART / mBART ─────────────────────────
    "d_model":                          int,
    "d_kv":                             int,
    "d_ff":                             int,
    "num_heads":                        int,
    "num_layers":                       int,
    "num_decoder_layers":               (int, type(None)),
    "encoder_attention_heads":          int,
    "decoder_attention_heads":          int,
    "encoder_ffn_dim":                  int,
    "decoder_ffn_dim":                  int,
    "encoder_layers":                   int,
    "decoder_layers":                   int,
    "dropout":                          float,
    "attention_dropout":                float,
    "activation_dropout":               float,
    "activation_function":              str,
    "scale_embedding":                  bool,
    "classifier_dropout":               (float, type(None)),
    "feed_forward_proj":                str,                 # T5
    "relative_attention_num_buckets":   int,                 # T5
    "relative_attention_max_distance":  int,                 # T5
    "dense_act_fn":                     str,                 # T5
    "is_gated_act":                     bool,                # T5
    "use_cache":                        bool,
    "init_std":                         float,               # BART
    "encoder_layerdrop":                float,               # BART
    "decoder_layerdrop":                float,               # BART
    "max_encoder_position_embeddings":  int,
    "max_decoder_position_embeddings":  int,

    # ── Whisper (음성) ──────────────────────────────
    "num_mel_bins":                     int,
    "max_source_positions":             int,
    "max_target_positions":             int,
    "input_stride":                     int,
    "chunk_length":                     int,
    "suppress_tokens":                  (list, type(None)),
    "begin_suppress_tokens":            (list, type(None)),
    "forced_decoder_ids":               (list, type(None)),
    "median_filter_width":              int,
    "apply_spec_augment":               bool,
    "mask_time_prob":                   float,
    "mask_time_length":                 int,
    "mask_time_min_masks":              int,
    "mask_feature_prob":                float,
    "mask_feature_length":              int,

    # ── Vision (ViT / CLIP / Swin) ────────────────
    "image_size":                       (int, list),
    "patch_size":                       int,
    "num_channels":                     int,
    "qkv_bias":                         bool,
    "encoder_stride":                   int,
    "num_stages":                       int,                 # Swin
    "window_size":                      int,                 # Swin
    "depths":                           list,                # Swin
    "embed_dim":                        int,                 # Swin/CLIP
    "mlp_ratio":                        float,
    "drop_path_rate":                   float,
    "hidden_dropout":                   float,
    "projection_dim":                   int,                 # CLIP
    "logit_scale_init_value":           float,               # CLIP

    # ── 멀티모달 서브 config (LLaVA / Qwen2-VL / Gemini 계열) ──
    # dict 타입: 내부에 모델별 파라미터를 담는 중첩 구조
    # 코드 실행 트리거가 아니라 순수 설정값이므로 안전
    "text_config":                      (dict, type(None)),
    "vision_config":                    (dict, type(None)),
    "audio_config":                     (dict, type(None)),
    "video_config":                     (dict, type(None)),

    # ── 멀티모달 특수 토큰 ID ──────────────────────
    # boi = begin of image, eoi = end of image
    # boa = begin of audio, eoa = end of audio
    "image_token_id":                   (int, type(None)),
    "video_token_id":                   (int, type(None)),
    "audio_token_id":                   (int, type(None)),
    "boi_token_id":                     (int, type(None)),
    "eoi_token_id":                     (int, type(None)),
    "boa_token_id":                     (int, type(None)),
    "eoa_token_id":                     (int, type(None)),
    "eoa_token_index":                  (int, type(None)),
    "image_token_index":                (int, type(None)),
    "video_token_index":                (int, type(None)),

    # ── 멀티모달 기타 ─────────────────────────────
    "vision_soft_tokens_per_image":     int,
    "num_image_tokens":                 int,
    "image_seq_length":                 int,

    # ── dtype 별칭 (일부 모델이 torch_dtype 대신 사용) ──
    "dtype":                            str,

    # ── 기타 공통 ──────────────────────────────────
    "model_max_length":                 (int, type(None)),
    "sep_token":                        (str, type(None)),
    "gradient_checkpointing":           bool,
    "tie_encoder_decoder":              bool,
    "quantization_config":              dict,
    "torch_dtype":                      str,
}

BLOCK_FIELDS = {
    "trust_remote_code": "외부 코드 무조건 실행 트리거",
}

ROUTE_TO_AST_FIELDS = {
    "auto_map":         "외부 .py 파일 참조 탐지",
    "custom_pipelines": "외부 파이프라인 .py 파일 참조 탐지",
}

URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)

ALLOWED_TOKENIZER_CLASSES = {
    # BERT 계열
    "BertTokenizer", "BertTokenizerFast",
    "AlbertTokenizer", "AlbertTokenizerFast",
    "DistilBertTokenizer", "DistilBertTokenizerFast",
    "ElectraTokenizer", "ElectraTokenizerFast",
    "RobertaTokenizer", "RobertaTokenizerFast",
    "XLMRobertaTokenizer", "XLMRobertaTokenizerFast",
    "CamembertTokenizer", "CamembertTokenizerFast",
    "DebertaTokenizer", "DebertaTokenizerFast",
    "DebertaV2Tokenizer", "DebertaV2TokenizerFast",
    # GPT 계열
    "GPT2Tokenizer", "GPT2TokenizerFast",
    "GPTNeoXTokenizerFast",
    "CodeGenTokenizer", "CodeGenTokenizerFast",
    # LLaMA / Mistral / Qwen / Gemma
    "LlamaTokenizer", "LlamaTokenizerFast",
    "MistralTokenizer",
    "Qwen2Tokenizer", "Qwen2TokenizerFast",
    "GemmaTokenizer", "GemmaTokenizerFast",
    "CodeLlamaTokenizer", "CodeLlamaTokenizerFast",
    # T5 / BART 계열
    "T5Tokenizer", "T5TokenizerFast",
    "BartTokenizer", "BartTokenizerFast",
    "MBartTokenizer", "MBartTokenizerFast",
    "MT5Tokenizer", "MT5TokenizerFast",
    "PegasusTokenizer", "PegasusTokenizerFast",
    # 음성
    "WhisperTokenizer", "WhisperTokenizerFast",
    "Wav2Vec2CTCTokenizer",
    # 비전
    "CLIPTokenizer", "CLIPTokenizerFast",
    # 기타
    "PreTrainedTokenizerFast",
    "XLNetTokenizer", "XLNetTokenizerFast",
    "MarianTokenizer",
    "BloomTokenizerFast",
    "FalconTokenizer",
}


# ────────────────────────────────────────────────
# 결과 구조
# ────────────────────────────────────────────────

@dataclass
class ValidationResult:
    filename: str
    status: str = "PASS"
    grade: str  = "A"
    flags: list = field(default_factory=list)   # 판정에 영향 O (보안 이슈)
    info: list  = field(default_factory=list)   # 판정에 영향 X (참고 로그)
    route_to_ast: list = field(default_factory=list)
    blocked_reason: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    _parsed_config: dict = field(default_factory=dict)  # 오탐 자동화용 파싱 결과 보관

    def block(self, reason: str):
        self.status = "BLOCKED"
        self.grade  = "C"
        self.blocked_reason = reason

    def flag(self, message: str):
        """판정에 영향을 주는 보안 이슈 — FLAGGED 상태로 격상"""
        if self.status != "BLOCKED":
            self.status = "FLAGGED"
            self.grade  = "B"
        self.flags.append(message)

    def log(self, message: str):
        """판정에 영향 없는 참고 로그 — 상태 변경 없음"""
        self.info.append(message)

    def add_ast_route(self, py_file: str, reason: str):
        if self.status != "BLOCKED":
            self.status = "FLAGGED"
            self.grade  = "B"
        self.route_to_ast.append({"file": py_file, "reason": reason})
        self.flags.append(f"AST 라우팅: {py_file} ({reason})")


# 마지막 검증 결과 전역 보관 (오탐 자동화용)
_LAST_RESULT: Optional[ValidationResult] = None


# ────────────────────────────────────────────────
# 검증 함수
# ────────────────────────────────────────────────

def step1_parse(raw: str, result: ValidationResult) -> Optional[dict]:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        result.block(f"JSON 파싱 실패 — {str(e).split('(')[0].strip()}")
        return None


# ── 값 패턴 검사용 상수 ──────────────────────────

# 모듈.클래스 패턴 (코드 참조 가능성)
MODULE_CLASS_PATTERN = re.compile(r'^[\w]+\.[\w]+$')

# 값에서 모듈.클래스 패턴 검사를 면제하는 필드
# (원래 점이 들어가는 게 정상인 필드들)
MODULE_PATTERN_EXEMPT = {
    "model_type", "hidden_act", "activation_function",
    "torch_dtype", "dtype", "feed_forward_proj", "dense_act_fn",
    "transformers_version", "_name_or_path", "tokenizer_class",
    # finetuning_task, problem_type 는 면제 제거
    # → "text-classification" 같은 값엔 점이 없음
    # → "evil.Exploit" 같은 패턴은 잡아야 함
}

# 허용된 model_type 목록
ALLOWED_MODEL_TYPES = {
    "bert", "roberta", "albert", "distilbert", "electra",
    "deberta", "deberta-v2", "xlm-roberta", "camembert",
    "xlnet", "longformer", "bigbird",
    "gpt2", "gpt_neo", "gpt_neox", "gptj", "gpt-j", "codegen",
    "llama", "mistral", "mixtral", "qwen2", "qwen2_vl",
    "gemma", "gemma2", "phi", "phi3", "falcon",
    "t5", "mt5", "bart", "mbart", "pegasus", "marian", "m2m_100",
    "whisper", "wav2vec2", "hubert", "seamless_m4t",
    "vit", "swin", "deit", "clip", "blip", "blip-2", "llava",
    "bloom", "opt", "mpt", "xglm",
    "encoder-decoder", "vision-encoder-decoder",
}

# 허용된 dtype 목록
ALLOWED_DTYPES = {
    "float32", "float16", "bfloat16", "float64",
    "int8", "int4", "auto",
}

# 허용된 활성화 함수 목록
ALLOWED_ACTIVATIONS = {
    "gelu", "gelu_new", "gelu_fast", "gelu_pytorch_tanh",
    "relu", "silu", "swish", "mish",
    "tanh", "sigmoid", "linear",
    "leaky_relu", "elu",
}


def _check_value_patterns(key: str, value, result: ValidationResult):
    """
    값 패턴 기반 추가 검사.
    필드 이름이 화이트리스트에 있어도 값이 의심스러우면 플래그.
    """
    if not isinstance(value, str):
        return

    # 1) 모든 문자열 필드 — URL 패턴
    if URL_PATTERN.match(value):
        result.flag(f"URL 값 탐지: '{key}' = '{value}' → 외부 리소스 참조 가능")
        return

    # 2) 면제 필드가 아닌 경우 — 모듈.클래스 패턴
    if key not in MODULE_PATTERN_EXEMPT and MODULE_CLASS_PATTERN.match(value):
        result.flag(f"모듈.클래스 패턴 탐지: '{key}' = '{value}' → 코드 참조 가능성")
        return

    # 3) 특정 필드 허용값 검사
    if key == "model_type" and value not in ALLOWED_MODEL_TYPES:
        result.log(f"미등록 model_type: '{value}' (참고)")

    if key in ("torch_dtype", "dtype") and value not in ALLOWED_DTYPES:
        result.flag(f"비허용 dtype 값: '{value}'")

    if key in ("hidden_act", "activation_function", "dense_act_fn") and value not in ALLOWED_ACTIVATIONS:
        result.log(f"미등록 활성화 함수: '{value}' (참고)")


def _type_ok(value, expected) -> bool:
    """
    타입 호환성 검사 — JSON 파싱 특성을 고려한 유연한 검사.

    핵심 규칙:
    - int 필드에 float(정수값) → 허용 (예: 10000.0)
    - float 필드에 int → 허용 (예: rope_theta: 10000)
    - bool 필드에 0/1 int → 허용
    - int 필드에 bool → 허용 (Python에서 bool은 int 서브클래스)
    - 튜플로 정의된 경우 → 하나라도 맞으면 허용
    """
    if isinstance(expected, tuple):
        return any(_type_ok(value, t) for t in expected)

    if expected is type(None):
        return value is None

    # bool 특수 처리 (Python에서 bool은 int 서브클래스라 먼저 체크)
    if expected is bool:
        return isinstance(value, (bool, int)) and value in (0, 1, True, False)

    if expected is int:
        # float인데 정수값이면 허용 (JSON에서 10000.0)
        if isinstance(value, float) and value.is_integer():
            return True
        # bool도 int로 허용
        return isinstance(value, (int, bool))

    if expected is float:
        # int도 float으로 허용 (JSON에서 10000 → float 필드)
        return isinstance(value, (float, int)) and not isinstance(value, bool)

    if expected is str:
        return isinstance(value, str)

    if expected is list:
        return isinstance(value, list)

    if expected is dict:
        return isinstance(value, dict)

    return isinstance(value, expected)


def step2_schema(config: dict, result: ValidationResult):
    for key, value in config.items():
        if key in BLOCK_FIELDS or key in ROUTE_TO_AST_FIELDS:
            continue

        if key not in ALLOWED_FIELDS:
            # 미등록 필드 — 값 패턴 검사 후 의심스러우면 플래그, 아니면 로그
            if isinstance(value, str):
                if URL_PATTERN.match(value):
                    result.flag(f"미등록 필드 + URL 값: '{key}' = '{value}'")
                elif MODULE_CLASS_PATTERN.match(value):
                    result.flag(f"미등록 필드 + 모듈.클래스 패턴: '{key}' = '{value}'")
                else:
                    result.log(f"미등록 필드: '{key}' (참고)")
            else:
                result.log(f"미등록 필드: '{key}' (참고)")
            continue

        # 타입 검사
        expected = ALLOWED_FIELDS[key]
        if not _type_ok(value, expected):
            expected_str = (
                " | ".join(t.__name__ if t is not type(None) else "None"
                           for t in expected)
                if isinstance(expected, tuple)
                else expected.__name__
            )
            result.flag(
                f"타입 불일치: '{key}' "
                f"(기대={expected_str}, 실제={type(value).__name__}, 값={repr(value)})"
            )

        # 값 패턴 검사 (화이트리스트 필드도 값 내용까지 검사)
        _check_value_patterns(key, value, result)

        # tokenizer_class 미등록 → 참고 로그
        if key == "tokenizer_class" and isinstance(value, str):
            if value not in ALLOWED_TOKENIZER_CLASSES:
                result.log(f"미등록 tokenizer_class: '{value}' (참고)")


def step3_dangerous(config: dict, result: ValidationResult):
    for fname, reason in BLOCK_FIELDS.items():
        if fname in config:
            result.block(f"위험 필드 '{fname}' 탐지 — {reason}")
            return
    for fname, reason in ROUTE_TO_AST_FIELDS.items():
        if fname in config:
            for f in _extract_py(config[fname]):
                result.add_ast_route(f, reason)


def _extract_py(val) -> list:
    out = set()
    if isinstance(val, dict):
        for v in val.values():
            if isinstance(v, str) and "." in v:
                out.add(v.split(".")[0] + ".py")
            elif isinstance(v, dict):
                impl = v.get("impl", "")
                if "." in impl:
                    out.add(impl.split(".")[0] + ".py")
    return list(out)


def validate(raw: str, filename: str = "config.json") -> ValidationResult:
    global _LAST_RESULT
    result = ValidationResult(filename=filename)

    _print_header(filename)

    # ① 파싱
    _print_step("① JSON 파싱", end=" ")
    config = step1_parse(raw, result)
    if config is None:
        print(red("FAIL"))
        _print_result(result)
        _LAST_RESULT = result
        return result
    print(green("OK"))

    # 파싱된 config 보관 (오탐 자동화용)
    result._parsed_config = config

    # ② 스키마 검증
    _print_step("② 스키마 검증", end=" ")
    before_flags = len(result.flags)
    step2_schema(config, result)
    added_flags = len(result.flags) - before_flags
    if added_flags:
        print(yellow(f"FLAGGED ({added_flags}건)"))
    elif result.info:
        print(yellow(f"INFO ({len(result.info)}건 참고 로그)"))
    else:
        print(green("OK"))

    # ③ 위험 필드 스캔
    _print_step("③ 위험 필드 스캔", end=" ")
    step3_dangerous(config, result)
    if result.status == "BLOCKED":
        print(red("BLOCKED"))
    elif result.route_to_ast:
        print(yellow(f"AST 라우팅 ({len(result.route_to_ast)}개 파일)"))
    else:
        print(green("OK"))

    # ④ 등급
    _print_step("④ 등급 결정", end=" ")
    grade_str = (green("A") if result.grade == "A" else
                 yellow("B") if result.grade == "B" else
                 red("C"))
    print(f"등급 {grade_str}")

    _print_result(result)
    _LAST_RESULT = result
    return result


def _print_header(filename: str):
    print(f"\n{bold('─' * 52)}")
    print(f"  🔍 검증 대상: {cyan(filename)}")
    print(bold('─' * 52))


def _print_step(name: str, end="\n"):
    print(f"  {blue(name):<30}", end=end)


def _print_result(result: ValidationResult):
    status_map = {
        "PASS":    green("✅ PASS    — 내부 저장소 전달"),
        "FLAGGED": yellow("⚠️  FLAGGED — 보안 담당자 검토 필요"),
        "BLOCKED": red("🚫 BLOCKED — 차단"),
    }
    print(f"\n  {'판정':<8}: {status_map[result.status]}")
    print(f"  {'등급':<8}: {bold(result.grade)}")
    print(f"  {'시각':<8}: {dim(result.timestamp)}")

    if result.blocked_reason:
        print(f"\n  {red('차단 사유')}:")
        print(f"    {result.blocked_reason}")

    if result.flags:
        print(f"\n  {yellow('🚨 보안 플래그')} {dim('(판정에 영향)')}:")
        for f in result.flags:
            print(f"    - {f}")

    if result.route_to_ast:
        print(f"\n  {cyan('AST 검증 라우팅')}:")
        for r in result.route_to_ast:
            print(f"    → {bold(r['file'])}  {dim('(' + r['reason'] + ')')}")

    if result.info:
        print(f"\n  {dim('📋 참고 로그')} {dim('(판정에 영향 없음)')}:")
        for i in result.info:
            print(f"    {dim('·')} {dim(i)}")
    print()


# ────────────────────────────────────────────────
# 데모 시나리오
# ────────────────────────────────────────────────

SCENARIOS = [
    ("✅  시나리오 1 — 정상 config.json (BERT)", """{
    "model_type": "bert",
    "architectures": ["BertForMaskedLM"],
    "hidden_size": 768,
    "num_hidden_layers": 12,
    "num_attention_heads": 12,
    "intermediate_size": 3072,
    "vocab_size": 30522,
    "hidden_act": "gelu",
    "hidden_dropout_prob": 0.1,
    "max_position_embeddings": 512,
    "torch_dtype": "float32",
    "transformers_version": "4.35.0"
}"""),

    ("⚠️   시나리오 2 — auto_map 탐지 → AST 라우팅", """{
    "model_type": "custom",
    "hidden_size": 1024,
    "num_hidden_layers": 24,
    "auto_map": {
        "AutoModel": "modeling_custom.MyCustomModel",
        "AutoTokenizer": "tokenization_custom.MyTokenizer"
    }
}"""),

    ("🚫  시나리오 3 — trust_remote_code → 즉시 차단", """{
    "model_type": "phi",
    "hidden_size": 2048,
    "num_hidden_layers": 32,
    "trust_remote_code": true,
    "auto_map": {
        "AutoModelForCausalLM": "modeling_phi.PhiForCausalLM"
    }
}"""),

    ("⚠️   시나리오 4 — 미등록 필드 + 외부 URL", """{
    "model_type": "bert",
    "hidden_size": 768,
    "_name_or_path": "https://attacker.com/malicious-model",
    "unknown_backdoor_field": "malicious_value",
    "vocab_size": 30522
}"""),

    ("⚠️   시나리오 5 — tokenizer_config custom_pipelines", """{
    "tokenizer_class": "PreTrainedTokenizerFast",
    "model_max_length": 512,
    "custom_pipelines": {
        "text-classification": {
            "impl": "pipelines_custom.MyPipeline",
            "pt": ["AutoModelForSequenceClassification"]
        }
    }
}"""),

    ("🚫  시나리오 6 — JSON 파싱 오류", """{
    "model_type": "bert",
    "hidden_size": 768
    "vocab_size": 30522
}"""),
]


# ────────────────────────────────────────────────
# 직접 입력 모드
# ────────────────────────────────────────────────

def interactive_mode():
    print(bold(cyan("\n[ 직접 입력 모드 ]")))
    print(dim("config.json 내용을 입력해. 입력 완료 후 빈 줄에서 Enter 두 번 누르면 검증 시작.\n"))

    lines = []
    empty_count = 0
    while True:
        try:
            line = input()
            if line == "":
                empty_count += 1
                if empty_count >= 2:
                    break
                lines.append(line)
            else:
                empty_count = 0
                lines.append(line)
        except EOFError:
            break

    raw = "\n".join(lines).strip()
    if not raw:
        print(yellow("입력값이 없어."))
        return

    validate(raw, filename="직접입력_config.json")


# ────────────────────────────────────────────────
# 요약 테이블
# ────────────────────────────────────────────────

def print_summary(results: list):
    print(bold(cyan("\n" + "═" * 52)))
    print(bold(cyan("  📊 전체 결과 요약")))
    print(bold(cyan("═" * 52)))
    print(f"  {'시나리오':<36} {'등급':^4}  {'상태'}")
    print(f"  {'─'*36} {'─'*4}  {'─'*10}")
    for title, r in results:
        short = title[:36]
        grade_c = green(r.grade) if r.grade == "A" else yellow(r.grade) if r.grade == "B" else red(r.grade)
        status_c = green(r.status) if r.status == "PASS" else yellow(r.status) if r.status == "FLAGGED" else red(r.status)
        print(f"  {short:<36} [{grade_c}]    {status_c}")
    print()


# ────────────────────────────────────────────────
# 화이트리스트 추가 요청 모드
# ────────────────────────────────────────────────

# 자동 검토 시 실행 트리거 가능성 있는 키워드
TRIGGER_KEYWORDS = [
    "map", "pipeline", "remote", "exec", "code",
    "script", "run", "call", "hook", "init", "load",
    "import", "spawn", "launch", "command",
]

# Pending List — 세션 동안 요청 누적
PENDING_LIST = []


def _auto_review(field: str, sample_value) -> dict:
    """
    필드 이름 + 샘플 값을 보고 화이트리스트 추가 가능 여부 자동 판단.
    반환: { auto_approve, reasons, need_manual }
    """
    reasons = []
    need_manual = False

    # ── 검사 1: 필드 이름에 실행 트리거 키워드 포함 여부 ──
    matched_keywords = [kw for kw in TRIGGER_KEYWORDS if kw in field.lower()]
    if matched_keywords:
        reasons.append(f"실행 트리거 키워드 포함: {matched_keywords}")
        need_manual = True

    # ── 검사 2: 값 타입 ──
    if sample_value is None:
        pass  # None은 안전
    elif isinstance(sample_value, (int, float, bool)):
        pass  # 숫자/불린은 안전
    elif isinstance(sample_value, str):
        # URL 패턴
        if URL_PATTERN.match(sample_value):
            reasons.append(f"값에 외부 URL 탐지: '{sample_value}'")
            need_manual = True
        # 모듈.클래스 패턴
        elif MODULE_CLASS_PATTERN.match(sample_value):
            reasons.append(f"값에 모듈.클래스 패턴 탐지: '{sample_value}'")
            need_manual = True
    elif isinstance(sample_value, list):
        # 리스트 내부 값도 검사
        for item in sample_value:
            if isinstance(item, str) and MODULE_CLASS_PATTERN.match(item):
                reasons.append(f"리스트 내부에 모듈.클래스 패턴: '{item}'")
                need_manual = True
                break
    elif isinstance(sample_value, dict):
        reasons.append("dict 타입 — 내부 구조 수동 확인 필요")
        need_manual = True
    else:
        reasons.append(f"알 수 없는 타입: {type(sample_value).__name__}")
        need_manual = True

    # ── 검사 3: 이미 위험 필드로 등록된 것과 이름이 유사한지 ──
    dangerous_names = set(BLOCK_FIELDS.keys()) | set(ROUTE_TO_AST_FIELDS.keys())
    for danger in dangerous_names:
        if danger in field.lower() or field.lower() in danger:
            reasons.append(f"위험 필드명과 유사: '{danger}'")
            need_manual = True
            break

    auto_approve = not need_manual
    if auto_approve:
        reasons.append("자동 검토 통과 — 담당자 최종 확인 후 추가 가능")

    return {
        "field":        field,
        "value":        sample_value,
        "auto_approve": auto_approve,
        "need_manual":  need_manual,
        "reasons":      reasons,
    }


def _print_review_result(r: dict):
    print(f"\n  {bold('─' * 46)}")
    print(f"  {'필드명':<10}: {cyan(r['field'])}")
    print(f"  {'샘플 값':<10}: {dim(str(r['value']))}")
    print()

    if r["auto_approve"]:
        print(f"  {green('✅ 자동 승인 권고')}")
        print(f"  {dim('담당자 최종 확인 후 화이트리스트에 추가 가능')}")
    else:
        print(f"  {yellow('⚠️  수동 리뷰 필요')}")
        print(f"  {dim('담당자가 직접 분석 후 결정해야 함')}")

    print(f"\n  {bold('검토 사유')}:")
    for reason in r["reasons"]:
        icon = green("✔") if r["auto_approve"] else yellow("!")
        print(f"    {icon} {reason}")
    print()


def _extract_unregistered_fields(result: ValidationResult) -> list:
    """
    마지막 검증 결과의 참고 로그에서
    미등록 필드 이름과 실제 값을 추출해서 반환.
    """
    unregistered = []
    for log_msg in result.info:
        # "미등록 필드: 'field_name' ..." 패턴에서 필드명 추출
        if "미등록 필드" in log_msg:
            match = re.search(r"'([^']+)'", log_msg)
            if match:
                field_name = match.group(1)
                # 파싱된 config에서 실제 값 가져오기
                value = result._parsed_config.get(field_name)
                unregistered.append((field_name, value))
    return unregistered



def whitelist_review_mode():
    print(bold(cyan("\n[ 화이트리스트 추가 요청 ]")))

    # ── 진입할 때마다 PENDING_LIST 초기화 ─────────────
    PENDING_LIST.clear()

    # 이미 화이트리스트에 있는 필드 + 파일에 저장된 필드 집합
    already_approved = set(ALLOWED_FIELDS.keys())
    if WHITELIST_FILE.exists():
        try:
            with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
                already_approved |= {e["field"] for e in json.load(f).get("approved", [])}
        except Exception:
            pass

    # ── 마지막 검증 결과에서 오탐 자동 로드 ──────────
    auto_loaded = []
    if _LAST_RESULT and _LAST_RESULT.info:
        unregistered = _extract_unregistered_fields(_LAST_RESULT)

        # 이미 승인된 필드 제거
        unregistered = [(f, v) for f, v in unregistered if f not in already_approved]

        if not unregistered:
            print(f"\n  {green('마지막 검증의 미등록 필드가 전부 이미 승인된 상태야.')}\n")
        else:
            print(f"\n  {yellow('마지막 검증에서 미등록 필드가 발견됐어.')}")
            print(f"  {dim(f'총 {len(unregistered)}개 (이미 승인된 필드 제외) — 자동으로 불러올까?')}\n")
            for field_name, val in unregistered:
                print(f"    · {cyan(field_name):<30} = {dim(str(val))}")
            print()
            choice = input(f"  {bold('자동으로 검토할까? (y/n)')} → ").strip().lower()
            if choice == "y":
                auto_loaded = unregistered

    # ── 자동 로드된 필드 일괄 검토 ───────────────────
    if auto_loaded:
        print(f"\n  {bold('─' * 46)}")
        print(f"  {bold('자동 로드된 오탐 필드 검토 결과')}")
        print(f"  {bold('─' * 46)}")
        seen = set()
        for field_name, val in auto_loaded:
            if field_name in seen:
                continue
            seen.add(field_name)
            r = _auto_review(field_name, val)
            _print_review_result(r)
            PENDING_LIST.append(r)

        more = input(f"  {dim('추가로 직접 입력할 필드도 있어? (y/n)')} → ").strip().lower()
        if more != "y":
            if PENDING_LIST:
                _print_pending_list()
            return

    else:
        print(dim("  오탐이 발생한 필드를 입력하면 화이트리스트 추가 가능 여부를 자동으로 검토해줘.\n"))

    # ── 수동 직접 입력 ────────────────────────────────
    seen_manual = set()
    while True:
        field = input(f"  {bold('필드 이름')} (나가려면 Enter) → ").strip()
        if not field:
            break

        if field in already_approved:
            print(yellow(f"  '{field}'는 이미 화이트리스트에 있어."))
            continue

        if field in seen_manual:
            print(yellow(f"  '{field}'는 이미 이번 세션에서 검토했어."))
            continue
        seen_manual.add(field)

        print(f"  {bold('샘플 값')} (없으면 Enter 그냥 눌러)")
        print(f"  {dim('예: 42  /  bfloat16  /  null  /  [1,2,3]')}")
        raw_val = input("  → ").strip()

        if not raw_val:
            sample_value = None
        else:
            try:
                sample_value = json.loads(raw_val)
            except json.JSONDecodeError:
                sample_value = raw_val

        r = _auto_review(field, sample_value)
        _print_review_result(r)
        PENDING_LIST.append(r)

        again = input(f"  {dim('다른 필드도 검토할까? (y/n)')} → ").strip().lower()
        if again != "y":
            break

    if PENDING_LIST:
        _print_pending_list()


# ────────────────────────────────────────────────
# 화이트리스트 파일 관리
# ────────────────────────────────────────────────

WHITELIST_FILE = Path("custom_whitelist.json")


def _infer_type_str(value) -> str:
    """샘플 값에서 타입 힌트 문자열 추론 (저장용)"""
    if value is None:
        return "None"
    elif isinstance(value, bool):
        return "bool"
    elif isinstance(value, int):
        return "int"
    elif isinstance(value, float):
        return "float"
    elif isinstance(value, str):
        return "str"
    elif isinstance(value, list):
        return "list"
    elif isinstance(value, dict):
        return "dict"
    return "str"


def load_custom_whitelist():
    """
    custom_whitelist.json 에서 승인된 필드를 읽어서
    ALLOWED_FIELDS 에 반영.
    """
    if not WHITELIST_FILE.exists():
        return

    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        type_map = {"int": int, "float": float, "bool": bool,
                    "str": str, "list": list, "dict": dict, "None": type(None)}

        added = 0
        for entry in data.get("approved", []):
            fname = entry.get("field")
            type_str = entry.get("type", "str")
            nullable = entry.get("nullable", False)

            if fname and fname not in ALLOWED_FIELDS:
                base_type = type_map.get(type_str, str)
                ALLOWED_FIELDS[fname] = (base_type, type(None)) if nullable else base_type
                added += 1

        if added:
            print(dim(f"  [custom_whitelist.json] 승인된 필드 {added}개 로드됨"))

    except Exception as e:
        print(yellow(f"  [경고] 화이트리스트 파일 로드 실패: {e}"))


def save_to_whitelist_file(approved_entries: list):
    """
    승인된 필드 목록을 custom_whitelist.json에 저장.
    기존 파일이 있으면 병합.
    """
    # 기존 파일 로드
    existing = {"approved": [], "history": []}
    if WHITELIST_FILE.exists():
        try:
            with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            pass

    existing_fields = {e["field"] for e in existing.get("approved", [])}

    # 새 항목 추가
    added = []
    for entry in approved_entries:
        if entry["field"] not in existing_fields:
            record = {
                "field":     entry["field"],
                "type":      _infer_type_str(entry["value"]),
                "nullable":  entry["value"] is None,
                "sample":    str(entry["value"]),
                "approved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "reasons":   entry["reasons"],
            }
            existing["approved"].append(record)
            added.append(entry["field"])

    # 히스토리 기록
    if added:
        existing.setdefault("history", []).append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": "approve",
            "fields": added,
        })

    with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(existing, f, ensure_ascii=False, indent=2)

    return added


def _apply_to_allowed_fields(entry: dict):
    """승인된 필드를 현재 세션 ALLOWED_FIELDS에 즉시 반영."""
    type_map = {"int": int, "float": float, "bool": bool,
                "str": str, "list": list, "dict": dict}
    type_str = _infer_type_str(entry["value"])
    base_type = type_map.get(type_str, str)
    nullable = entry["value"] is None
    ALLOWED_FIELDS[entry["field"]] = (base_type, type(None)) if nullable else base_type


def _print_pending_list():
    print(f"\n{bold('─' * 52)}")
    print(bold(f"  📋 Pending List ({len(PENDING_LIST)}건)"))
    print(bold('─' * 52))

    auto_ok  = [r for r in PENDING_LIST if r["auto_approve"]]
    need_rev = [r for r in PENDING_LIST if r["need_manual"]]

    if auto_ok:
        print(f"\n  {green('✅ 자동 승인 권고')} ({len(auto_ok)}건)")
        for i, r in enumerate(auto_ok, 1):
            print(f"    {cyan(str(i))}. {r['field']:<28} = {dim(str(r['value']))}")

    if need_rev:
        print(f"\n  {yellow('⚠️  수동 리뷰 필요')} ({len(need_rev)}건)")
        for r in need_rev:
            print(f"    ? {yellow(r['field']):<30} {dim(', '.join(r['reasons']))}")

    # ── 자동 승인 권고 항목 처리 ──────────────────────
    if not auto_ok:
        print(f"\n  {dim('자동 승인 권고 항목이 없어.')}")
        print()
        return

    print(f"\n  {bold('화이트리스트에 추가할 항목을 선택해.')}")
    print(f"  {dim('번호 입력 (예: 1 3 5) / all = 전체 / n = 취소')}")
    raw = input(f"  → ").strip().lower()

    if raw == "n" or not raw:
        print(dim("  취소됨."))
        print()
        return

    # 선택 파싱
    if raw == "all":
        selected = auto_ok
    else:
        try:
            indices = [int(x) - 1 for x in raw.split()]
            selected = [auto_ok[i] for i in indices if 0 <= i < len(auto_ok)]
        except ValueError:
            print(red("  올바른 번호를 입력해줘."))
            print()
            return

    if not selected:
        print(dim("  선택된 항목 없음."))
        print()
        return

    # ── 파일 저장 + 세션 즉시 반영 ───────────────────
    added = save_to_whitelist_file(selected)
    for entry in selected:
        _apply_to_allowed_fields(entry)

    print(f"\n  {green('✅ 저장 완료')}")
    print(f"  {dim(f'파일: {WHITELIST_FILE.resolve()}')}")
    print(f"\n  {bold('추가된 필드:')}")
    for fname in added:
        print(f"    + {green(fname)}")

    print(f"\n  {dim('세션에도 즉시 반영됐어. 지금 바로 검증 다시 돌려봐.')}")
    print()


# ────────────────────────────────────────────────
# 메인 메뉴
# ────────────────────────────────────────────────

def print_banner():
    print(bold(cyan("\n" + "═" * 52)))
    print(bold(cyan("  AI 모델 공급망 보안 프록시")))
    print(bold(cyan("  config.json 검증 파이프라인 데모")))
    print(bold(cyan("  캡스톤디자인 프로젝트")))
    print(bold(cyan("═" * 52)))


def print_menu():
    print(f"\n{bold('[ 메뉴 ]')}")
    print(f"  {cyan('1')}  전체 시나리오 자동 실행")
    print(f"  {cyan('2')}  시나리오 선택 실행")
    print(f"  {cyan('3')}  직접 config.json 입력")
    print(f"  {cyan('4')}  화이트리스트 추가 요청")
    print(f"  {cyan('0')}  종료")
    print()


def scenario_menu():
    print(f"\n{bold('[ 시나리오 선택 ]')}")
    for i, (title, _) in enumerate(SCENARIOS, 1):
        print(f"  {cyan(str(i))}  {title}")
    print(f"  {cyan('0')}  뒤로")
    print()


def run_all_scenarios() -> list:
    results = []
    for title, raw in SCENARIOS:
        print(f"\n{bold(title)}")
        r = validate(raw)
        results.append((title, r))
    print_summary(results)
    return results


def run_selected_scenario():
    scenario_menu()
    choice = input(f"  {bold('번호 입력')} → ").strip()
    if choice == "0":
        return
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(SCENARIOS):
            title, raw = SCENARIOS[idx]
            print(f"\n{bold(title)}")
            validate(raw)
        else:
            print(red("  없는 번호야."))
    except ValueError:
        print(red("  숫자를 입력해줘."))


def main():
    print_banner()
    load_custom_whitelist()  # 시작할 때 저장된 화이트리스트 자동 로드

    while True:
        print_menu()
        choice = input(f"  {bold('선택')} → ").strip()

        if choice == "1":
            run_all_scenarios()

        elif choice == "2":
            run_selected_scenario()

        elif choice == "3":
            interactive_mode()

        elif choice == "4":
            whitelist_review_mode()

        elif choice == "0":
            print(f"\n{dim('종료.')}\n")
            break

        else:
            print(red("  0~4 중에 입력해줘."))

        input(dim("\n  계속하려면 Enter..."))


if __name__ == "__main__":
    main()
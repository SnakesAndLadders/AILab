import re
import unicodedata
from typing import Any, Dict, Optional
from guardrails import Guard  # type: ignore
from guardrails.validator_base import (  # type: ignore
    FailResult,
    PassResult,
    ValidationResult,
    Validator,
    register_validator,
)
from optimum.onnxruntime import ORTModelForSequenceClassification  # type: ignore
from transformers import AutoTokenizer, pipeline  # type: ignore


@register_validator(name="kaby-lake-hybrid-shield", data_type="string")
class KabyLakeHybridShield(Validator):
    """Two-stage validator: Instant Unicode/Regex filter + Local ONNX DeBERTa ML classifier."""

    INJECTION_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?(previous|prior|above|system)\s+(instructions|prompts|rules|directives)",
        r"(?i)disregard\s+(all\s+)?(previous|prior|your)\s+(instructions|programming|constraints)",
        r"(?i)you\s+are\s+now\s+(in\s+)?(developer|admin|god|unrestricted|DAN|jailbreak)\s+mode",
        r"(?i)new\s+system\s+(prompt|instruction|override)\s*:",
        r"(?i)\[\s*(system|admin|override|assistant)\s*\]",
        r"(?i)(execute|run|invoke)\s+(bash|shell|terminal|command|rm\s+-rf|curl|wget)",
        r"(?i)(read|cat|exfiltrate|send|upload)\s+(/etc/passwd|\.env|\.ssh|id_rsa|api[_\s]?key)",
    ]

    TOXICITY_PATTERNS = [
        r"(?i)\b(kill\s+yourself|build\s+a\s+bomb|how\s+to\s+synthesize\s+ricin)\b",
        r"(?i)\b(ransomware\s+payload|steal\s+credentials\s+script)\b",
    ]

    ZERO_WIDTH_CHARS = re.compile(r"[\u200B-\u200D\uFEFF\u2060]")

    def __init__(self, injection_threshold: float = 0.85, **kwargs):
        super().__init__(injection_threshold=injection_threshold, **kwargs)
        self.injection_threshold = injection_threshold

        # Load pre-baked ONNX DeBERTa classifier once into RAM
        tokenizer = AutoTokenizer.from_pretrained("/app/onnx_model")
        model = ORTModelForSequenceClassification.from_pretrained("/app/onnx_model")
        self.classifier = pipeline(
            "text-classification",
            model=model,
            tokenizer=tokenizer,
            truncation=True,
            max_length=512,
        )

    def validate(self, value: str, metadata: Optional[Dict[str, Any]] = None) -> ValidationResult:
        # --- STAGE 1: Fast Deterministic Pre-Filter ---
        if self.ZERO_WIDTH_CHARS.search(value):
            return FailResult(
                error_message="Blocked (Stage 1): Hidden zero-width Unicode characters detected.",
                fix_value=self.ZERO_WIDTH_CHARS.sub("", value),
            )

        normalized = unicodedata.normalize("NFKC", value)

        for pattern in self.INJECTION_PATTERNS:
            if re.search(pattern, normalized):
                return FailResult(
                    error_message="Blocked (Stage 1): Deterministic prompt injection signature matched."
                )

        for pattern in self.TOXICITY_PATTERNS:
            if re.search(pattern, normalized):
                return FailResult(
                    error_message="Blocked (Stage 1): High-risk toxicity or dangerous content detected."
                )

        # --- STAGE 2: Local ONNX DeBERTa Semantic Classifier ---
        prediction = self.classifier(normalized)
        label = prediction.get("label", "")
        score = float(prediction.get("score", 0.0))

        if label == "INJECTION" and score >= self.injection_threshold:
            return FailResult(
                error_message=f"Blocked (Stage 2 ML): Semantic prompt injection detected (confidence: {score:.2f})."
            )

        return PassResult(validated_value=normalized)


# Register the Guard instance named 'input-guard' for LiteLLM
input_guard = Guard(name="input-guard").use(
    KabyLakeHybridShield(injection_threshold=0.85, on_fail="exception")
)

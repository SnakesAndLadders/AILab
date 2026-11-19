import re
import unicodedata
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from guardrails import Guard
from guardrails.validator_base import (
    FailResult,
    PassResult,
    ValidationResult,
    Validator,
    register_validator,
)
from optimum.onnxruntime import ORTModelForSequenceClassification
from transformers import AutoTokenizer, pipeline


@register_validator(name="hybrid-prompt-injection-shield", data_type="string")
class HybridPromptInjectionShield(Validator):
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

        results = self.classifier(normalized)
        prediction = results[0] if isinstance(results, list) and results else {}
        label = prediction.get("label", "")
        score = float(prediction.get("score", 0.0))


        if label == "INJECTION" and score >= self.injection_threshold:
            return FailResult(
                error_message=f"Blocked (Stage 2 ML): Semantic prompt injection detected (confidence: {score:.2f})."
            )

        return PassResult(validated_value=normalized)


guard = Guard().use(HybridPromptInjectionShield(injection_threshold=0.85, on_fail="exception"))
app = FastAPI(title="Guardrails Hybrid Shield")


class ValidateRequest(BaseModel):
    llmOutput: Optional[str] = None
    text: Optional[str] = None
    input: Optional[str] = None
    messages: Optional[List[Dict[str, Any]]] = None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/guards/{guard_id}/validate")
def validate_guard(guard_id: str, req: ValidateRequest):
    payload = req.llmOutput or req.text or req.input or ""
    if not payload and req.messages:
        payload = "\n".join(str(m.get("content", "")) for m in req.messages)

    try:
        outcome = guard.validate(payload)
        return {
            "validationPassed": outcome.validation_passed,
            "validatedOutput": outcome.validated_output,
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

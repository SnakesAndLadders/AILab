import re
import unicodedata
from typing import Any, Dict, Optional
from guardrails import Guard
from guardrails.validator_base import (
    FailResult,
    PassResult,
    ValidationResult,
    Validator,
    register_validator,
)


@register_validator(name="nehalem-safe-shield", data_type="string")
class NehalemSafeShield(Validator):
    """CPU-only validator for prompt injection, hidden unicode, and toxicity."""

    INJECTION_PATTERNS = [
        # Direct & Indirect Instruction Overrides
        r"(?i)ignore\s+(all\s+)?(previous|prior|above|system)\s+(instructions|prompts|rules|directives)",
        r"(?i)disregard\s+(all\s+)?(previous|prior|your)\s+(instructions|programming|constraints)",
        r"(?i)you\s+are\s+now\s+(in\s+)?(developer|admin|god|unrestricted|DAN|jailbreak)\s+mode",
        r"(?i)new\s+system\s+(prompt|instruction|override)\s*:",
        r"(?i)\[\s*(system|admin|override|assistant)\s*\]",
        # Agent Tool & Exfiltration Hijacking (Critical for OpenClaw)
        r"(?i)(execute|run|invoke)\s+(bash|shell|terminal|command|rm\s+-rf|curl|wget)",
        r"(?i)(read|cat|exfiltrate|send|upload)\s+(/etc/passwd|\.env|\.ssh|id_rsa|api[_\s]?key)",
    ]

    TOXICITY_PATTERNS = [
        r"(?i)\b(kill\s+yourself|build\s+a\s+bomb|how\s+to\s+synthesize\s+ricin)\b",
        r"(?i)\b(ransomware\s+payload|steal\s+credentials\s+script)\b",
    ]

    # Invisible zero-width characters often used to smuggle injections past filters
    ZERO_WIDTH_CHARS = re.compile(r"[\u200B-\u200D\uFEFF\u2060]")

    def validate(self, value: str, metadata: Optional[Dict[str, Any]] = None) -> ValidationResult:
        # 1. Check for hidden zero-width smuggling characters
        if self.ZERO_WIDTH_CHARS.search(value):
            return FailResult(
                error_message="Blocked: Hidden zero-width Unicode characters detected.",
                fix_value=self.ZERO_WIDTH_CHARS.sub("", value),
            )

        # 2. Normalize homoglyphs (e.g., Cyrillic 'а' masquerading as Latin 'a')
        normalized = unicodedata.normalize("NFKC", value)

        # 3. Scan for Prompt Injection & Agent Hijacking
        for pattern in self.INJECTION_PATTERNS:
            if re.search(pattern, normalized):
                return FailResult(
                    error_message=f"Blocked: Prompt injection pattern matched ({pattern})."
                )

        # 4. Scan for Toxicity / Dangerous Content
        for pattern in self.TOXICITY_PATTERNS:
            if re.search(pattern, normalized):
                return FailResult(
                    error_message="Blocked: High-risk toxicity or dangerous content detected."
                )

        return PassResult(validated_value=normalized)


# Register the Guard instance named 'input-guard' for the Guardrails Server API
input_guard = Guard(name="input-guard").use(
    NehalemSafeShield(on_fail="exception")
)

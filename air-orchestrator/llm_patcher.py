#!/usr/bin/env python3
"""
AIR LLM 패치 생성기 — Anthropic Messages API (의존성 없음 / urllib)

탐지된 공격 + 취약 소스 파일을 Claude(claude-opus-4-8)에 보내 '수정된 전체 파일'을 받는다.
ANTHROPIC_API_KEY 가 없거나 호출 실패/거부 시 None 반환 → 호출측이 템플릿으로 폴백(하이브리드).
"""
import json, os, urllib.request, urllib.error

API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-opus-4-8"
ANTHROPIC_VERSION = "2023-06-01"

SYSTEM = (
    "You are AIR's automated security patch engineer for a Spring Boot e-commerce app. "
    "You receive one vulnerable Java source file and a description of a live attack that "
    "exploited it. Return a corrected version of the ENTIRE file that closes the "
    "vulnerability UNCONDITIONALLY (not behind a runtime feature flag), preserves all "
    "other behavior, and compiles cleanly. Output ONLY the full file content — no markdown "
    "fences, no commentary, no explanation."
)

def _strip_fences(text):
    text = text.strip()
    if "```" in text:
        parts = text.split("```")
        if len(parts) >= 3:
            block = parts[1]
            nl = block.find("\n")
            if nl != -1 and block[:nl].strip().replace("+", "").isalpha():
                block = block[nl + 1:]   # drop ```java language tag line
            return block.strip("\n") + "\n"
    return text.strip("\n") + "\n"

def generate_patch(file_rel_path, original_code, incident):
    """수정된 전체 파일 내용(str) 또는 None(미사용/실패/거부) 반환."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("[llm] ANTHROPIC_API_KEY 없음 → 템플릿 폴백")
        return None

    user = (
        f"Vulnerability type: {incident.get('type')}\n"
        f"Endpoint attacked: {incident.get('endpoint')}\n"
        f"Attack payload: {incident.get('payload')}\n"
        f"File path: {file_rel_path}\n\n"
        f"--- BEGIN {file_rel_path} ---\n{original_code}\n--- END {file_rel_path} ---\n\n"
        f"Return the full corrected contents of {file_rel_path}. The fix must defend against "
        f"this attack unconditionally (the running app must reject it even if every runtime "
        f"defense flag is OFF). Output the file content only."
    )
    body = {
        "model": MODEL,
        "max_tokens": 8000,
        "system": SYSTEM,
        "thinking": {"type": "adaptive"},
        "output_config": {"effort": "high"},
        "messages": [{"role": "user", "content": user}],
    }
    req = urllib.request.Request(API_URL, data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("x-api-key", api_key)
    req.add_header("anthropic-version", ANTHROPIC_VERSION)

    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            resp = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        print(f"[llm] API 오류 {e.code}: {e.read().decode()[:300]} → 템플릿 폴백")
        return None
    except Exception as e:
        print(f"[llm] 호출 실패: {e} → 템플릿 폴백")
        return None

    if resp.get("stop_reason") == "refusal":
        print("[llm] 안전 거부(refusal) → 템플릿 폴백")
        return None

    text = "".join(b.get("text", "") for b in resp.get("content", []) if b.get("type") == "text")
    if not text.strip():
        print("[llm] 빈 응답 → 템플릿 폴백")
        return None

    usage = resp.get("usage", {})
    print(f"[llm] 패치 생성 완료 (in={usage.get('input_tokens')} out={usage.get('output_tokens')})")
    return _strip_fences(text)

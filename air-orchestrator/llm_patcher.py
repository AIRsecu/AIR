#!/usr/bin/env python3
"""
AIR LLM 패치/분류 생성기 — 멀티 공급자 (의존성 없음 / urllib)

공급자 선택: 환경변수 AIR_LLM_PROVIDER = anthropic | gemini | groq
  (미설정 시 존재하는 키로 자동 감지: ANTHROPIC_API_KEY → GEMINI_API_KEY → GROQ_API_KEY)

무료 옵션(결제 불필요, 가입만):
  - Gemini : https://aistudio.google.com → "Get API key" → GEMINI_API_KEY (선택 GEMINI_MODEL)
  - Groq   : https://console.groq.com   → API Keys           → GROQ_API_KEY  (선택 GROQ_MODEL)
유료:
  - Anthropic : console.anthropic.com (크레딧 필요) → ANTHROPIC_API_KEY

키가 하나도 없거나 호출 실패/거부 시 None 반환 → 호출측이 템플릿/휴리스틱/shield 로 폴백(하이브리드).
"""
import json, os, urllib.request, urllib.error

ANTHROPIC_URL     = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL   = "claude-opus-4-8"
ANTHROPIC_VERSION = "2023-06-01"
GEMINI_MODEL_DEFAULT = "gemini-2.0-flash"
GROQ_URL          = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL_DEFAULT = "llama-3.3-70b-versatile"

PATCH_SYSTEM = (
    "You are AIR's automated security patch engineer for a Spring Boot e-commerce app. "
    "You receive one vulnerable Java source file and a description of a live attack that "
    "exploited it. Return a corrected version of the ENTIRE file that closes the "
    "vulnerability UNCONDITIONALLY (not behind a runtime feature flag), preserves all "
    "other behavior, and compiles cleanly. Output ONLY the full file content — no markdown "
    "fences, no commentary, no explanation."
)
CLASSIFY_SYSTEM = (
    "You are AIR's autonomous security analyst for a Spring Boot e-commerce API. "
    "An anomaly-based detector (not a signature) flagged suspicious activity and a broad "
    "shield was already applied to the source. Decide whether it is a real attack and, if so, "
    "author ONE minimal runtime block rule for the app's rule engine. Prefer the most precise "
    "field available (block the offending source IP for scans/floods; use a query/path substring "
    "for content attacks). Output JSON ONLY, no prose, no markdown fences."
)


def _provider():
    p = (os.environ.get("AIR_LLM_PROVIDER") or "").strip().lower()
    if p in ("anthropic", "gemini", "groq"):
        return p
    if os.environ.get("ANTHROPIC_API_KEY"): return "anthropic"
    if os.environ.get("GEMINI_API_KEY"):    return "gemini"
    if os.environ.get("GROQ_API_KEY"):      return "groq"
    return None


def _http(url, headers, body, timeout):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST")
    for k, v in headers.items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _call_llm(system, user, max_tokens=1500, timeout=120):
    """공급자별 호출 → 텍스트(str) 또는 None(무키/실패/거부)."""
    prov = _provider()
    if not prov:
        print("[llm] LLM 키 없음(ANTHROPIC/GEMINI/GROQ) → 폴백")
        return None
    try:
        if prov == "anthropic":
            resp = _http(ANTHROPIC_URL,
                {"Content-Type": "application/json",
                 "x-api-key": os.environ["ANTHROPIC_API_KEY"],
                 "anthropic-version": ANTHROPIC_VERSION},
                {"model": ANTHROPIC_MODEL, "max_tokens": max_tokens, "system": system,
                 "messages": [{"role": "user", "content": user}]}, timeout)
            if resp.get("stop_reason") == "refusal":
                print("[llm] anthropic 거부 → 폴백"); return None
            text = "".join(b.get("text", "") for b in resp.get("content", []) if b.get("type") == "text")
            return text or None

        if prov == "gemini":
            model = os.environ.get("GEMINI_MODEL", GEMINI_MODEL_DEFAULT)
            url = (f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
                   f"?key={os.environ['GEMINI_API_KEY']}")
            resp = _http(url, {"Content-Type": "application/json"},
                {"systemInstruction": {"parts": [{"text": system}]},
                 "contents": [{"role": "user", "parts": [{"text": user}]}],
                 "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0.2}}, timeout)
            cands = resp.get("candidates") or []
            if not cands:
                print("[llm] gemini 빈 응답 → 폴백"); return None
            parts = cands[0].get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in parts)
            return text or None

        if prov == "groq":
            model = os.environ.get("GROQ_MODEL", GROQ_MODEL_DEFAULT)
            resp = _http(GROQ_URL,
                {"Content-Type": "application/json",
                 "Authorization": "Bearer " + os.environ["GROQ_API_KEY"]},
                {"model": model, "max_tokens": max_tokens, "temperature": 0.2,
                 "messages": [{"role": "system", "content": system},
                              {"role": "user", "content": user}]}, timeout)
            ch = resp.get("choices") or []
            return (ch[0].get("message", {}).get("content") if ch else None) or None
    except urllib.error.HTTPError as e:
        print(f"[llm] {prov} API 오류 {e.code}: {e.read().decode()[:200]} → 폴백")
        return None
    except Exception as e:
        print(f"[llm] {prov} 호출 실패: {e} → 폴백")
        return None
    return None


def _strip_fences(text):
    text = text.strip()
    if "```" in text:
        parts = text.split("```")
        if len(parts) >= 3:
            block = parts[1]
            nl = block.find("\n")
            if nl != -1 and block[:nl].strip().replace("+", "").isalpha():
                block = block[nl + 1:]   # drop ```java / ```json language tag line
            return block.strip("\n") + "\n"
    return text.strip("\n") + "\n"


def generate_patch(file_rel_path, original_code, incident):
    """수정된 전체 파일 내용(str) 또는 None(미사용/실패) 반환 — 소스패치(5단계)."""
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
    text = _call_llm(PATCH_SYSTEM, user, max_tokens=8000, timeout=600)
    if not text or not text.strip():
        return None
    return _strip_fences(text)


def classify_and_rule(incident):
    """이상/미지 인시던트를 LLM이 분류하고 동적룰 제안. dict 또는 None(무키/실패) — Stage3."""
    user = (
        "Anomaly incident:\n"
        f"  type: {incident.get('type')}\n"
        f"  endpoint: {incident.get('endpoint')}\n"
        f"  clientIp: {incident.get('clientIp')}\n"
        f"  signal/payload: {incident.get('payload')}\n\n"
        "Rule schema (all fields optional, matched with AND; empty string = ignore):\n"
        '  ip, method("*"=any), pathContains, contains(query substring), action("BLOCK")\n\n'
        "Respond ONLY with compact JSON of this exact shape:\n"
        '{"is_attack": true, "attack_class": "...", "severity": "low|medium|high", '
        '"rule": {"ip":"","method":"*","pathContains":"","contains":"","action":"BLOCK"}, '
        '"relax_shield": true, "reason": "..."}'
    )
    text = _call_llm(CLASSIFY_SYSTEM, user, max_tokens=1200, timeout=120)
    if not text or not text.strip():
        return None
    try:
        return json.loads(_strip_fences(text).strip())
    except Exception as e:
        print(f"[llm] 분류 JSON 파싱 실패({e}): {text[:200]} → 폴백")
        return None

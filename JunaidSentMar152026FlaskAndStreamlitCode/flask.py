from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import json
import re
import asyncio
import os
from datetime import datetime, timezone

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

audit_log = []
event_stream = []


def now():
    return datetime.now(timezone.utc).isoformat()


"""
=====================================================
ATTACK DETECTION RULES
(Ported from SecurityAgent version-V1)
=====================================================
"""

# ---------------------------------------------------------------------------
# Sensitive file patterns
# ---------------------------------------------------------------------------
SENSITIVE_FILES = [
    ".env", ".env.local", ".env.production", ".env.staging",
    "id_rsa", "id_ed25519", "id_ecdsa",
    "authorized_keys", ".ssh/config",
    "credentials.json", "secrets.yaml", "secrets.yml", "secrets.json",
    ".aws/credentials", ".aws/config", ".azure/credentials",
    ".npmrc", ".pypirc", ".netrc",
    ".docker/config.json", "kubeconfig", ".kube/config",
    "terraform.tfvars", ".vault-token",
    "service-account.json", "private_key.json",
]

# ---------------------------------------------------------------------------
# Exfiltration commands
# ---------------------------------------------------------------------------
EXFIL_COMMANDS = [
    "curl", "wget", "scp", "nc", "netcat",
]

# ---------------------------------------------------------------------------
# Prompt injection / evasion patterns
# ---------------------------------------------------------------------------
PROMPT_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all prior instructions",
    "reveal system prompt",
    "show hidden prompt",
    "developer instructions",
    "bypass safety",
]

EVASION_PATTERNS = [
    {"pattern": r"\b(ignore|bypass|skip|disable|override)\s+(your\s+)?(security|safety|filter|rule|restriction|guard)s?\b", "label": "security_bypass_request"},
    {"pattern": r"\b(pretend|act\s+as\s+if|imagine)\s+(you\s+)?(are|have|can)\s+(unrestricted|admin|root)\b", "label": "role_play_bypass"},
    {"pattern": r"\bjailbreak\b", "label": "jailbreak_keyword"},
    {"pattern": r"\b(don.?t|do\s*not)\s+(scan|check|filter|block|flag)\b", "label": "disable_scanning_request"},
    {"pattern": r"\b(base64|encode|decode|hex|rot13)\s+.{0,30}(\.env|secret|key|password|credential|shadow|token)\b", "label": "encoding_evasion"},
]

# ---------------------------------------------------------------------------
# Regex-based exfiltration detection
# ---------------------------------------------------------------------------
EXFIL_REGEXES = [
    r"curl\s+.*https?://",
    r"wget\s+.*https?://",
]

# ---------------------------------------------------------------------------
# PII patterns (DLP) — detect sensitive data in LLM responses
# ---------------------------------------------------------------------------
DLP_PII_PATTERNS = {
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "Credit Card": r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{3,4}\b",
    "Email Address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "US Phone": r"\b(?:\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b",
    "IBAN": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b",
}

# ---------------------------------------------------------------------------
# Credential patterns — detect leaked secrets in responses
# ---------------------------------------------------------------------------
CREDENTIAL_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
    "Generic API Key": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?",
    "Generic Secret": r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?",
    "JWT Token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "GitHub Token": r"gh[ps]_[A-Za-z0-9_]{36,}",
    "Slack Token": r"xox[bprs]-[A-Za-z0-9-]+",
    "Private Key Header": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Database URL": r"(?i)(postgres|mysql|mongodb|redis)://[^\s]+:[^\s]+@[^\s]+",
    "Stripe Key": r"sk_live_[A-Za-z0-9]{20,}",
}

# ---------------------------------------------------------------------------
# Prompt risk keywords — weighted scoring (from SecurityAgent)
# ---------------------------------------------------------------------------
PROMPT_RISK_KEYWORDS = {
    "pii_request": [
        {"pattern": r"\b(ssn|social\s*security\s*number)s?\b", "weight": 0.6},
        {"pattern": r"\b(customer|client|user|employee)\s+(data|info|information|details|record)s?\b", "weight": 0.3},
        {"pattern": r"\bpersonal\s+(data|info|information|details)\b", "weight": 0.4},
        {"pattern": r"\b(dates?\s*of\s*birth|dob|birthdate)s?\b", "weight": 0.3},
        {"pattern": r"\b(passport|driver.?s?\s*license|national\s*id)\s*(number|data|info)?\b", "weight": 0.5},
        {"pattern": r"\bpii\b", "weight": 0.5},
    ],
    "credential_request": [
        {"pattern": r"\b(api\s*key|secret\s*key|access\s*key|private\s*key)s?\b", "weight": 0.6},
        {"pattern": r"\b(passwords?|passwd|credentials?)\b", "weight": 0.4},
        {"pattern": r"\b(token|auth\s*token|bearer\s*token|jwt)s?\b", "weight": 0.3},
        {"pattern": r"(\.env\b|environment\s*variable|env\s*var)s?\b", "weight": 0.4},
        {"pattern": r"\b(aws|gcp|azure)\s*(secret|credential|key)s?\b", "weight": 0.5},
        {"pattern": r"\b(database|db)\s*(password|credential|connection\s*string)\b", "weight": 0.5},
    ],
    "financial_request": [
        {"pattern": r"\b(credit\s*card|card\s*number|cvv|pan)\s*(data|number|info)?\b", "weight": 0.6},
        {"pattern": r"\b(bank\s*account|routing\s*number|account\s*number)\b", "weight": 0.5},
        {"pattern": r"\b(bank\s*statement|tax\s*return|w-?2|1099|payroll)\b", "weight": 0.4},
        {"pattern": r"\b(salary|compensation|pay\s*(stub|check|slip))\b", "weight": 0.3},
    ],
    "medical_request": [
        {"pattern": r"\b(patient|medical|health)\s*(record|data|file|history|info)s?\b", "weight": 0.5},
        {"pattern": r"\b(diagnos[ei]s|prescription|treatment\s*plan|lab\s*result)s?\b", "weight": 0.5},
        {"pattern": r"\b(hipaa|phi|protected\s*health)\b", "weight": 0.6},
        {"pattern": r"\b(npi|provider\s*id|member\s*id|insurance\s*id)\b", "weight": 0.4},
    ],
    "exfiltration_intent": [
        {"pattern": r"\b(send|upload|post|transmit|exfil)\s+(to|the|this|that|it|data|file)\b", "weight": 0.4},
        {"pattern": r"\b(curl|wget|fetch)\s+.{0,40}(https?://|ftp://|webhook)\b", "weight": 0.5},
        {"pattern": r"\b(copy|transfer|move)\s+.{0,30}(to\s+)?.{0,20}(server|remote|external|cloud)\b", "weight": 0.5},
    ],
    "bulk_data_request": [
        {"pattern": r"\b(all|every|entire|complete|full)\s+.{0,20}(customer|patient|user|employee|client).{0,20}(data|record|file|ssn|social|info|detail)s?\b", "weight": 0.6},
        {"pattern": r"\b(dump|export|extract)\s+(the\s+)?(database|db|table|collection)\b", "weight": 0.6},
        {"pattern": r"\b(bulk|mass|batch)\s+(download|export|extract|read)\b", "weight": 0.4},
    ],
}

# ---------------------------------------------------------------------------
# High-risk compound patterns (multi-signal, high confidence)
# ---------------------------------------------------------------------------
COMPOUND_PATTERNS = [
    {"pattern": r"\b(customer|patient|user)\s+(data|record).{0,60}\b(send|upload|curl|email|post)\b", "label": "data_request_plus_exfil", "weight": 0.8},
    {"pattern": r"\b(password|secret|key|credential).{0,60}\b(pipe|redirect|curl|send|post)\b", "label": "credential_plus_exfil", "weight": 0.9},
    {"pattern": r"\b(get|give|show|list|find|fetch)\s+.{0,10}(all|every)\s+.{0,30}(ssn|password|credit\s*card|patient|api\s*key|social\s*security)\b", "label": "get_all_sensitive", "weight": 0.8},
    {"pattern": r"\b(show|give|list|get|find)\s+.{0,20}\ball\b.{0,20}\b(password|credential|secret|token|key|ssn)s?\b", "label": "show_all_credentials", "weight": 0.8},
    {"pattern": r"\b(dump|extract)\s+.{0,30}\b(password|credential|secret|token|api.?key|config)s?\b", "label": "dump_credentials", "weight": 0.8},
    {"pattern": r"\b(select|update|delete)\b.{0,60}\b(ssn|social.security|credit.card|password|dob|date.of.birth)\b", "label": "sql_pii_extraction", "weight": 0.8},
    {"pattern": r"\b(find|get|show|list|export)\s+(all|every)?\s*.{0,30}\b(patient|medical|health)\s*(record|data|file|history)s?\b", "label": "hipaa_bulk_access", "weight": 0.8},
]

# Pre-compile all regex patterns
_COMPILED_RISK = {
    cat: [(re.compile(p["pattern"], re.IGNORECASE), p["weight"]) for p in patterns]
    for cat, patterns in PROMPT_RISK_KEYWORDS.items()
}
_COMPILED_COMPOUND = [
    (re.compile(p["pattern"], re.IGNORECASE), p["label"], p["weight"])
    for p in COMPOUND_PATTERNS
]
_COMPILED_EVASION = [
    (re.compile(p["pattern"], re.IGNORECASE), p["label"])
    for p in EVASION_PATTERNS
]
_COMPILED_PII = {
    name: re.compile(pattern) for name, pattern in DLP_PII_PATTERNS.items()
}
_COMPILED_CREDS = {
    name: re.compile(pattern) for name, pattern in CREDENTIAL_PATTERNS.items()
}


def detect_attack(prompt="", command=""):
    """Simple detection for tool calls and basic prompt checks."""

    text = f"{prompt} {command}".lower()

    # Prompt injection
    for p in PROMPT_INJECTION_PATTERNS:
        if p in text:
            return {
                "category": "prompt_injection",
                "reason": f"Prompt injection phrase detected: {p}",
                "severity": "high",
            }

    # Secret access
    for s in SENSITIVE_FILES:
        if s in text:
            return {
                "category": "secret_access",
                "reason": f"Sensitive file reference detected: {s}",
                "severity": "critical",
            }

    # Exfil commands
    for e in EXFIL_COMMANDS:
        if e in text:
            return {
                "category": "data_exfiltration",
                "reason": f"Exfiltration command detected: {e}",
                "severity": "critical",
            }

    # Regex exfil detection
    for r_pattern in EXFIL_REGEXES:
        if re.search(r_pattern, text):
            return {
                "category": "data_exfiltration",
                "reason": "External data transmission detected",
                "severity": "critical",
            }

    return None


def analyze_prompt(prompt):
    """Deep prompt analysis with weighted risk scoring (from SecurityAgent).

    Returns:
        dict with risk_score, risk_level, categories, matches, should_block
    """
    prompt_lower = prompt.lower()
    matches = []
    categories_hit = set()
    total_weight = 0.0

    # Phase 1: Keyword/pattern matching by category
    for category, compiled_list in _COMPILED_RISK.items():
        for compiled_re, weight in compiled_list:
            if compiled_re.search(prompt_lower):
                matches.append({
                    "category": category,
                    "pattern": compiled_re.pattern,
                    "weight": weight,
                })
                categories_hit.add(category)
                total_weight += weight

    # Phase 2: Compound patterns (multi-signal, high confidence)
    for compiled_re, label, weight in _COMPILED_COMPOUND:
        if compiled_re.search(prompt_lower):
            matches.append({
                "category": "compound",
                "pattern": label,
                "weight": weight,
            })
            total_weight += weight

    # Phase 3: Evasion detection
    evasion_flags = []
    for compiled_re, label in _COMPILED_EVASION:
        if compiled_re.search(prompt_lower):
            evasion_flags.append(label)
            total_weight += 0.3

    risk_score = min(1.0, total_weight)

    if risk_score >= 0.7:
        risk_level = "high"
    elif risk_score >= 0.4:
        risk_level = "medium"
    elif risk_score >= 0.15:
        risk_level = "low"
    else:
        risk_level = "none"

    return {
        "risk_score": round(risk_score, 3),
        "risk_level": risk_level,
        "intent_categories": sorted(categories_hit),
        "matches": matches[:10],
        "evasion_flags": evasion_flags,
        "should_block": risk_level == "high",
    }


def scan_for_pii(text):
    """Scan text for PII and credential patterns (DLP).

    Returns list of findings.
    """
    findings = []
    for name, compiled_re in _COMPILED_PII.items():
        for match in compiled_re.finditer(text):
            value = match.group(0)
            redacted = value[:4] + "***" if len(value) > 6 else "***"
            findings.append({"type": "pii", "pattern": name, "preview": redacted})

    for name, compiled_re in _COMPILED_CREDS.items():
        for match in compiled_re.finditer(text):
            value = match.group(0)
            redacted = value[:4] + "***" if len(value) > 6 else "***"
            findings.append({"type": "credential", "pattern": name, "preview": redacted})

    return findings


"""
=====================================================
EVENT STREAM (REAL-TIME DASHBOARD)
=====================================================
"""


async def event_generator():

    last_index = 0

    while True:

        if len(event_stream) > last_index:

            event = event_stream[last_index]
            last_index += 1

            yield f"data: {json.dumps(event)}\n\n"

        await asyncio.sleep(0.25)


@app.get("/events")
async def events():

    return StreamingResponse(event_generator(), media_type="text/event-stream")


"""
=====================================================
ROOT
=====================================================
"""


@app.get("/")
def root():

    return {
        "status": "AI Security Policy Engine Running",
        "time": now(),
        "events_logged": len(audit_log),
    }


@app.get("/monitor", response_class=HTMLResponse)
def monitor():

    html_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    with open(html_path) as f:
        return f.read()


"""
=====================================================
PROMPT POLICY CHECK
=====================================================
"""


@app.post("/prompt")
async def prompt(req: Request):

    data = await req.json()
    prompt = data.get("prompt", "")

    print("\n================ USER PROMPT =================")
    print(prompt)
    print("==============================================\n")

    attack = detect_attack(prompt=prompt)

    event = {
        "type": "prompt",
        "time": now(),
        "data": data,
        "attack": attack,
    }

    audit_log.append(event)
    event_stream.append(event)

    if attack:

        print("🚨 PROMPT ATTACK DETECTED:", attack)

        return {
            "block": True,
            "reason": attack["reason"],
        }

    return {"block": False}


"""
=====================================================
TOOL POLICY CHECK
=====================================================
"""


@app.post("/check")
async def check(req: Request):

    data = await req.json()

    print("\n================ TOOL REQUEST =================")
    print(json.dumps(data, indent=2))
    print("===============================================\n")

    args = data.get("args", {})
    command = ""

    if isinstance(args, dict):
        command = args.get("command", "")

    attack = detect_attack(command=command)

    event = {
        "type": "tool_request",
        "time": now(),
        "data": data,
        "attack": attack,
    }

    audit_log.append(event)
    event_stream.append(event)

    if attack:

        print("🚨 TOOL ATTACK DETECTED:", attack)

        return {
            "allow": False,
            "reason": attack["reason"],
        }

    return {"allow": True}


"""
=====================================================
TOOL RESULT
=====================================================
"""


@app.post("/result")
async def result(req: Request):

    data = await req.json()

    event = {
        "type": "tool_result",
        "time": now(),
        "data": data,
    }

    audit_log.append(event)
    event_stream.append(event)

    return {"ok": True}


"""
=====================================================
LLM RESPONSE
=====================================================
"""


@app.post("/response")
async def response(req: Request):

    data = await req.json()

    event = {
        "type": "assistant_response",
        "time": now(),
        "data": data,
    }

    audit_log.append(event)
    event_stream.append(event)

    return {"ok": True}


"""
=====================================================
RAW LLM INPUT (before LLM API call)
=====================================================
"""


@app.post("/llm-input")
async def llm_input(req: Request):

    data = await req.json()

    print("\n================ RAW LLM INPUT =================")
    print(f"Provider: {data.get('provider')}")
    print(f"Model: {data.get('model')}")
    print(f"System Prompt: {str(data.get('systemPrompt', ''))[:200]}")
    print(f"Prompt: {str(data.get('prompt', ''))[:200]}")
    print(f"History Messages: {data.get('historyMessageCount')}")
    print("=================================================\n")

    prompt = data.get("prompt", "")

    # Layer 1: Simple pattern detection (prompt injection, sensitive files)
    attack = detect_attack(prompt=prompt)

    # Layer 2: Deep prompt analysis with weighted risk scoring
    analysis = analyze_prompt(prompt)

    event = {
        "type": "llm_input",
        "time": now(),
        "data": data,
        "attack": attack,
        "analysis": analysis,
    }

    audit_log.append(event)
    event_stream.append(event)

    # Block on simple pattern match
    if attack:
        print("🚨 LLM INPUT ATTACK DETECTED:", attack)
        return {"block": True, "reason": attack["reason"]}

    # Block on high risk score from deep analysis
    if analysis["should_block"]:
        reason = f"High risk prompt (score={analysis['risk_score']}, categories={analysis['intent_categories']})"
        print(f"🚨 LLM INPUT BLOCKED BY RISK ANALYSIS: {reason}")
        return {"block": True, "reason": reason}

    # Warn on medium risk (log but don't block)
    if analysis["risk_level"] == "medium":
        print(f"⚠️ MEDIUM RISK PROMPT: score={analysis['risk_score']}, categories={analysis['intent_categories']}")

    return {"block": False, "analysis": analysis}


"""
=====================================================
RAW LLM OUTPUT (after LLM API response)
=====================================================
"""


@app.post("/llm-output")
async def llm_output(req: Request):

    data = await req.json()

    print("\n================ RAW LLM OUTPUT =================")
    print(f"Provider: {data.get('provider')}")
    print(f"Model: {data.get('model')}")
    print(f"Usage: {data.get('usage')}")
    texts = data.get("assistantTexts", [])
    print(f"Response preview: {str(texts[0])[:200] if texts else 'N/A'}")
    print("==================================================\n")

    # DLP scan: check LLM response for PII/credential leakage
    combined_text = " ".join(texts) if texts else ""
    pii_findings = scan_for_pii(combined_text)

    event = {
        "type": "llm_output",
        "time": now(),
        "data": data,
        "pii_findings": pii_findings if pii_findings else None,
    }

    audit_log.append(event)
    event_stream.append(event)

    if pii_findings:
        print(f"🚨 DLP ALERT: {len(pii_findings)} PII/credential pattern(s) in LLM response:")
        for f in pii_findings:
            print(f"   - {f['type']}: {f['pattern']} ({f['preview']})")

    return {"ok": True, "pii_findings": pii_findings}


"""
=====================================================
SECURITY DASHBOARD
=====================================================
"""


@app.get("/dashboard")
def dashboard():

    stats = {
        "total_events": len(audit_log),
        "prompt_attacks": 0,
        "secret_access": 0,
        "exfiltration": 0,
        "tool_calls": 0,
        "high_risk_prompts": 0,
        "medium_risk_prompts": 0,
        "pii_leaks": 0,
    }

    for e in audit_log:

        if e["type"] in ("prompt", "llm_input") and e.get("attack"):

            if e["attack"]["category"] == "prompt_injection":
                stats["prompt_attacks"] += 1

            if e["attack"]["category"] == "secret_access":
                stats["secret_access"] += 1

            if e["attack"]["category"] == "data_exfiltration":
                stats["exfiltration"] += 1

        # Count risk-scored prompts
        analysis = e.get("analysis")
        if analysis:
            if analysis.get("risk_level") == "high":
                stats["high_risk_prompts"] += 1
            elif analysis.get("risk_level") == "medium":
                stats["medium_risk_prompts"] += 1

        # Count PII leaks in LLM output
        if e.get("pii_findings"):
            stats["pii_leaks"] += len(e["pii_findings"])

        if e["type"] in ("tool_request", "llm_input", "llm_output"):
            stats["tool_calls"] += 1

    return {"stats": stats, "recent_events": audit_log[-25:]}


"""
=====================================================
RUN SERVER
=====================================================
"""

if __name__ == "__main__":

    uvicorn.run(app, host="0.0.0.0", port=8000)

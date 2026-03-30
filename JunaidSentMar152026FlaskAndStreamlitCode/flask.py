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
=====================================================
"""

SENSITIVE_FILES = [
    ".env",
    "id_rsa",
    "id_ed25519",
    "authorized_keys",
    "credentials",
    "secrets",
    ".aws/credentials",
]

EXFIL_COMMANDS = [
    "curl",
    "wget",
    "scp",
    "nc",
    "netcat",
]

PROMPT_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all prior instructions",
    "reveal system prompt",
    "show hidden prompt",
    "developer instructions",
    "bypass safety",
]

EXFIL_REGEXES = [
    r"curl\s+.*https?://",
    r"wget\s+.*https?://",
]


def detect_attack(prompt="", command=""):

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
    for r in EXFIL_REGEXES:
        if re.search(r, text):
            return {
                "category": "data_exfiltration",
                "reason": "External data transmission detected",
                "severity": "critical",
            }

    return None


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

    # Only scan the user prompt, not the system prompt (which contains
    # internal tool descriptions that trigger false positives).
    attack = detect_attack(prompt=prompt)

    event = {
        "type": "llm_input",
        "time": now(),
        "data": data,
        "attack": attack,
    }

    audit_log.append(event)
    event_stream.append(event)

    if attack:
        print("🚨 LLM INPUT ATTACK DETECTED:", attack)
        return {"block": True, "reason": attack["reason"]}

    return {"block": False}


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

    event = {
        "type": "llm_output",
        "time": now(),
        "data": data,
    }

    audit_log.append(event)
    event_stream.append(event)

    return {"ok": True}


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
    }

    for e in audit_log:

        if e["type"] == "prompt" and e.get("attack"):

            if e["attack"]["category"] == "prompt_injection":
                stats["prompt_attacks"] += 1

            if e["attack"]["category"] == "secret_access":
                stats["secret_access"] += 1

            if e["attack"]["category"] == "data_exfiltration":
                stats["exfiltration"] += 1

        if e["type"] == "tool_request":
            stats["tool_calls"] += 1

    return {"stats": stats, "recent_events": audit_log[-25:]}


"""
=====================================================
RUN SERVER
=====================================================
"""

if __name__ == "__main__":

    uvicorn.run(app, host="0.0.0.0", port=8000)

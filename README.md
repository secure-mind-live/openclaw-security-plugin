# OpenClaw Security Plugin

A security plugin for OpenClaw that intercepts AI agent activity (prompts, tool calls, responses), runs them through a policy engine, and displays everything on a real-time dashboard.

## What We Built

- **OpenClaw Plugin** (`index.ts`) — Hooks into four OpenClaw lifecycle events: `message_received`, `before_tool_call`, `after_tool_call`, `message_sent`. Forwards all payloads to a FastAPI policy engine for inspection.
- **FastAPI Policy Engine** (`flask.py`) — Receives intercepted data, runs attack detection rules (prompt injection, secret access, data exfiltration), blocks or allows requests, and maintains an audit log with SSE event stream.
- **Real-time HTML Dashboard** (`dashboard.html`) — Connects to the `/events` SSE endpoint. Shows live event feed with attack highlighting.
- **Streamlit Dashboard** (`dashboard.py`) — Polls `/dashboard` for stats. Shows metric cards (total events, prompt attacks, secret access, exfiltration) and a pie chart of attack categories.

## Architecture

```
+------------------+         +---------------------+         +-------------------+
|                  |         |                     |         |                   |
|   OpenClaw       |  HTTP   |   FastAPI Policy    |  SSE    |   Dashboard       |
|   AI Agent       +-------->+   Engine (:8000)    +-------->+   (HTML/Streamlit)|
|                  |         |                     |         |                   |
+--------+---------+         +----------+----------+         +-------------------+
         |                              |
         |  Plugin hooks:               |  Endpoints:
         |  - message_received          |  - POST /prompt    (prompt check)
         |  - before_tool_call          |  - POST /check     (tool check)
         |  - after_tool_call           |  - POST /result    (tool result log)
         |  - message_sent              |  - POST /response  (LLM response log)
         |                              |  - GET  /events    (SSE stream)
         |                              |  - GET  /dashboard (stats JSON)
         |                              |
         v                              v
+-----------------------------------------------------------+
|                    Attack Detection Rules                  |
|                                                           |
|  - Prompt injection phrases ("ignore previous", etc.)     |
|  - Sensitive file access (.env, id_rsa, credentials)      |
|  - Exfiltration commands (curl, wget, scp, nc)            |
|  - Regex patterns for external data transmission          |
+-----------------------------------------------------------+
```

### Flow

```
User prompt --> Plugin (message_received) --> POST /prompt --> detect_attack()
                                                               |
                                                     block = true/false
                                                               |
            <-- throw Error if blocked <-----------------------+

Tool call   --> Plugin (before_tool_call) --> POST /check  --> detect_attack()
                                                               |
                                                     allow = true/false
                                                               |
            <-- throw Error if blocked <-----------------------+

Tool result --> Plugin (after_tool_call)  --> POST /result --> log only

LLM reply   --> Plugin (message_sent)     --> POST /response --> log only
```

## What We Were Able To Do

- Register a custom plugin with OpenClaw and have it load on agent startup
- Intercept user prompts before they reach the LLM
- Intercept tool calls (bash, file read/write, etc.) before and after execution
- Capture the final LLM response sent back to the user
- Block prompts and tool calls in real-time based on policy rules
- Stream all events to a live SOC-style dashboard

## OpenClaw Limitation Observed

**No hook to intercept the raw LLM request/response.**

OpenClaw exposes hooks for user messages and tool calls, but there is no hook that fires at the point where the actual API call is made to the LLM provider (e.g., the raw HTTP request to Anthropic/OpenAI). This means:

- We can see what the user typed (`message_received`) and what the LLM replied (`message_sent`), but we cannot see or modify the full prompt payload that gets sent to the LLM API — including system prompts, conversation history assembly, or any internal prompt augmentation OpenClaw performs.
- We cannot inspect or alter the raw LLM response before OpenClaw processes it into tool calls or messages.
- This limits the ability to build a full security proxy that audits exactly what goes over the wire to the model provider.

In short: the plugin sits at the application layer (user messages, tool calls), not at the transport layer (raw LLM API calls).

## Running

```bash
# Build the plugin
npm run build

# Start the policy engine
cd JunaidSentMar152026FlaskAndStreamlitCode
python flask.py

# Open the HTML dashboard
open dashboard.html

# Or run the Streamlit dashboard
streamlit run dashboard.py
```

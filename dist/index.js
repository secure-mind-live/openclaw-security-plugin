"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const axios_1 = __importDefault(require("axios"));
const POLICY_API = "http://host.docker.internal:8000/check";
const RESULT_API = "http://host.docker.internal:8000/result";
const PROMPT_API = "http://host.docker.internal:8000/prompt";
const RESPONSE_API = "http://host.docker.internal:8000/response";
const LLM_INPUT_API = "http://host.docker.internal:8000/llm-input";
const LLM_OUTPUT_API = "http://host.docker.internal:8000/llm-output";
exports.default = {
    register(api) {
        console.log("[Security Auditor] Plugin registered.");
        /*
        ======================================
        USER PROMPT INTERCEPTION
        ======================================
        */
        api.on("message_received", async (event) => {
            const prompt = event?.content ||
                event?.message ||
                event?.text ||
                "";
            const payload = {
                type: "user_prompt",
                prompt: prompt,
                user: event?.user || "junaid",
                runId: event?.runId || null,
                timestamp: new Date().toISOString()
            };
            console.log("\n========== USER PROMPT ==========");
            console.log(prompt);
            console.log("=================================\n");
            try {
                const response = await axios_1.default.post(PROMPT_API, payload, { timeout: 2000 });
                if (response.data?.block === true) {
                    console.log("🚨 PROMPT BLOCKED BY POLICY");
                    throw new Error(`Policy Block: ${response.data.reason}`);
                }
            }
            catch (err) {
                if (err.message?.includes("Policy Block")) {
                    throw err;
                }
                console.error("[Security Auditor] Policy engine unreachable");
                throw new Error("Security Block: Policy engine offline");
            }
        });
        /*
        ======================================
        BEFORE TOOL EXECUTION
        ======================================
        */
        api.on("before_tool_call", async (event) => {
            const payload = {
                type: "tool_call_request",
                tool: event?.toolName || "unknown",
                args: event?.params || {},
                user: event?.user || "junaid",
                runId: event?.runId || null,
                timestamp: new Date().toISOString()
            };
            console.log("\n========== BEFORE TOOL ==========");
            console.log(JSON.stringify(payload, null, 2));
            console.log("=================================\n");
            try {
                const response = await axios_1.default.post(POLICY_API, payload, { timeout: 2000 });
                if (response.data?.allow === false) {
                    console.log("🚨 TOOL EXECUTION BLOCKED");
                    throw new Error(`Policy Block: ${response.data.reason}`);
                }
            }
            catch (err) {
                if (err.message?.includes("Policy Block")) {
                    throw err;
                }
                console.error("Policy engine unreachable.");
                throw new Error("Security Block: Policy engine offline.");
            }
        });
        /*
        ======================================
        AFTER TOOL EXECUTION
        ======================================
        */
        api.on("after_tool_call", async (event) => {
            const payload = {
                type: "tool_call_result",
                tool: event?.toolName || "unknown",
                result: event?.result || null,
                user: event?.user || "junaid",
                timestamp: new Date().toISOString()
            };
            console.log("\n========== TOOL RESULT ==========");
            console.log(JSON.stringify(payload, null, 2));
            console.log("=================================\n");
            try {
                await axios_1.default.post(RESULT_API, payload, { timeout: 2000 });
            }
            catch (err) {
                console.error("[Security Auditor] Failed sending result:", err.message);
            }
        });
        /*
        ======================================
        RAW LLM INPUT INTERCEPTION
        ======================================
        */
        api.on("llm_input", async (event) => {
            const payload = {
                type: "llm_input",
                runId: event?.runId || null,
                sessionId: event?.sessionId || null,
                provider: event?.provider || "unknown",
                model: event?.model || "unknown",
                systemPrompt: event?.systemPrompt || null,
                prompt: event?.prompt || "",
                historyMessageCount: event?.historyMessages?.length || 0,
                imagesCount: event?.imagesCount || 0,
                timestamp: new Date().toISOString()
            };
            console.log("\n========== LLM INPUT ==========");
            console.log("Provider:", payload.provider);
            console.log("Model:", payload.model);
            console.log("System Prompt:", event?.systemPrompt?.substring(0, 200));
            console.log("Prompt:", event?.prompt?.substring(0, 200));
            console.log("History Messages:", payload.historyMessageCount);
            console.log("================================\n");
            try {
                const response = await axios_1.default.post(LLM_INPUT_API, payload, { timeout: 2000 });
                if (response.data?.block === true) {
                    console.log("🚨 LLM CALL BLOCKED BY POLICY");
                    return {
                        block: true,
                        blockReason: response.data.reason || "Blocked by security policy"
                    };
                }
                if (response.data?.prompt) {
                    return { prompt: response.data.prompt };
                }
            }
            catch (err) {
                console.error("[Security Auditor] LLM input policy check failed:", err.message);
            }
        });
        /*
        ======================================
        RAW LLM OUTPUT INTERCEPTION
        ======================================
        */
        api.on("llm_output", async (event) => {
            const payload = {
                type: "llm_output",
                runId: event?.runId || null,
                sessionId: event?.sessionId || null,
                provider: event?.provider || "unknown",
                model: event?.model || "unknown",
                assistantTexts: event?.assistantTexts || [],
                usage: event?.usage || null,
                timestamp: new Date().toISOString()
            };
            console.log("\n========== LLM OUTPUT ==========");
            console.log("Provider:", payload.provider);
            console.log("Model:", payload.model);
            console.log("Usage:", JSON.stringify(payload.usage));
            console.log("Response preview:", event?.assistantTexts?.[0]?.substring(0, 200));
            console.log("=================================\n");
            try {
                const response = await axios_1.default.post(LLM_OUTPUT_API, payload, { timeout: 2000 });
                if (response.data?.assistantTexts) {
                    return { assistantTexts: response.data.assistantTexts };
                }
            }
            catch (err) {
                console.error("[Security Auditor] LLM output policy check failed:", err.message);
            }
        });
        /*
        ======================================
        FINAL LLM RESPONSE
        ======================================
        */
        api.on("message_sent", async (event) => {
            const response = event?.message ||
                event?.content ||
                "";
            const payload = {
                type: "assistant_response",
                response: response,
                user: event?.user || "junaid",
                timestamp: new Date().toISOString()
            };
            console.log("\n========== LLM RESPONSE ==========");
            console.log(response);
            console.log("==================================\n");
            try {
                await axios_1.default.post(RESPONSE_API, payload, { timeout: 2000 });
            }
            catch (err) {
                console.error("[Security Auditor] Failed sending response:", err.message);
            }
        });
    }
};

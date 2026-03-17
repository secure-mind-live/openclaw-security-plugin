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

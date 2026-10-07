import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createAgentSessionServices } from "@earendil-works/pi-coding-agent";

// Opt-in, billable tests. Credentials come from the caller's environment only.
const provider = process.argv[2];
assert.ok(provider === "nearai" || provider === "tinfoil", "Pass nearai or tinfoil, optionally followed by a model ID.");
const keyName = provider === "nearai" ? "NEARAI_API_KEY" : "TINFOIL_API_KEY";
const key = process.env[keyName];
assert.ok(key, `Set ${keyName} without placing it in command arguments.`);
const policyName = provider === "nearai" ? "PI_NEARAI_POLICY" : "PI_TINFOIL_POLICY";
const root = process.cwd();
await mkdir(".scratch/work", { recursive: true });
const scratch = await mkdtemp(resolve(".scratch/work/pi-live-"));
const cwd = join(scratch, "project");
const agentDir = join(scratch, "agent");
const entry = resolve("packages", provider, "dist/extension.js");
const testExtension = join(scratch, "synthetic.ts");
await mkdir(cwd);
await mkdir(agentDir, { mode: 0o700 });
await writeFile(join(agentDir, "settings.json"), JSON.stringify({ compaction: { enabled: false }, retry: { enabled: false } }));
await writeFile(testExtension, `
export default function(pi) {
  let requests = 0;
  pi.on("before_provider_request", event => {
    const payload = event.payload;
    return { ...payload,
      ...(Object.hasOwn(payload, "max_tokens") ? { max_tokens: 1024 } : { max_completion_tokens: 1024 }),
      ...(++requests > 4 ? { model: "live-test-request-limit" } : {}),
    };
  });
  pi.on("after_provider_response", () => { process.stdout.write(JSON.stringify({type:"live_response_headers"}) + "\\n"); });
  pi.registerTool({
    name: "synthetic_echo", label: "Synthetic echo", description: "Echo the synthetic test value.",
    parameters: { type: "object", properties: {value: {type:"string"}}, required:["value"], additionalProperties:false },
    async execute(_id, args) {
      if(args.value !== "pi-tee-π") throw Error("unexpected synthetic value");
      return {content:[{type:"text",text:"echo:"+args.value}],details:{}};
    },
  });
}
`);

type Event = Record<string, any>;

async function runCli(model: string, prompt: string, options: { tool?: boolean; thinking?: string; cancel?: boolean } = {}) {
  const env: NodeJS.ProcessEnv = { ...process.env, PI_CODING_AGENT_DIR: agentDir, [policyName]: "sdk", PI_NEARAI_MODEL_VISIBILITY: "tee" };
  delete env.NEARAI_API_KEY;
  delete env.TINFOIL_API_KEY;
  // The real key is in Pi's isolated store: a successful call also checks stored-key precedence.
  env[keyName] = "synthetic-invalid-environment-key";
  const args = [resolve(root, "node_modules/@earendil-works/pi-coding-agent/dist/cli.js"),
    "--provider", provider!, "--model", model, "--thinking", options.thinking ?? "off",
    "--no-session", "--no-extensions", "--no-skills", "--no-prompt-templates", "--no-mcp",
    "--system-prompt", "Follow the user's synthetic test instructions concisely.",
    "-e", entry, "-e", testExtension,
    ...(options.tool ? ["--tools", "synthetic_echo"] : ["--no-tools"]),
    "--mode", options.cancel ? "rpc" : "json", ...(options.cancel ? [] : ["-p", prompt]),
  ];
  const child = spawn(process.execPath, args, { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
  const events: Event[] = [];
  let pending = "";
  let bytes = 0;
  let timedOut = false;
  let abortSent = false;
  let headersSeen = false;
  let abortTimer: ReturnType<typeof setTimeout> | undefined;
  let forceTimer: ReturnType<typeof setTimeout> | undefined;
  const terminate = () => {
    child.kill("SIGTERM");
    forceTimer ??= setTimeout(() => child.kill("SIGKILL"), 5000);
  };
  const abort = () => {
    if (abortSent) return;
    abortSent = true;
    child.stdin.write(JSON.stringify({ type: "abort", id: "cancel" }) + "\n");
  };
  const deadline = setTimeout(() => { timedOut = true; terminate(); }, 120_000);
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    bytes += Buffer.byteLength(chunk);
    if (bytes > 4 * 1024 * 1024) { timedOut = true; terminate(); return; }
    pending += chunk;
    let newline: number;
    while ((newline = pending.indexOf("\n")) !== -1) {
      const line = pending.slice(0, newline); pending = pending.slice(newline + 1);
      let event: Event;
      try { event = JSON.parse(line); } catch { continue; }
      if (!event || typeof event !== "object") continue;
      events.push(event);
      if (!options.cancel) continue;
      if (event.type === "message_start" && event.message?.role === "assistant") abortTimer ??= setTimeout(abort, 15_000);
      if (event.type === "live_response_headers") { headersSeen = true; abort(); }
      if (event.type === "agent_end" || (event.type === "response" && event.id === "cancel")) child.stdin.end();
    }
  });
  // Consume diagnostics without writing provider data or credentials to ordinary logs.
  child.stderr.resume();
  if (options.cancel) child.stdin.write(JSON.stringify({ type: "prompt", id: "prompt", message: prompt }) + "\n");
  else child.stdin.end();
  let exitCode: number | null;
  try { exitCode = await new Promise<number | null>((resolve, reject) => { child.once("close", resolve); child.once("error", reject); }); }
  finally { clearTimeout(deadline); if (abortTimer) clearTimeout(abortTimer); if (forceTimer) clearTimeout(forceTimer); }
  assert.ok(!timedOut, "Pi live test timed out or exceeded its output cap.");
  assert.equal(exitCode, 0, "Pi CLI did not exit cleanly.");
  const assistants = events.filter(e => e.type === "message_end" && e.message?.role === "assistant").map(e => e.message);
  assert.ok(assistants.length > 0, "Pi produced no completed assistant message.");
  return { events, assistants, headersSeen };
}

function accepted(assistants: Event[]) {
  const rejected = assistants.find(m => m.stopReason === "error" || m.stopReason === "aborted");
  assert.ok(!rejected, `Pi rejected live inference: ${/^TEE_[A-Z_]+$/.test(rejected?.errorMessage ?? "") ? rejected!.errorMessage : "unspecified terminal error"}`);
  assert.ok(assistants.some(m => m.usage?.totalTokens > 0), "No positive usage was returned.");
}

const oldPolicy = process.env[policyName];
const oldVisibility = process.env.PI_NEARAI_MODEL_VISIBILITY;
try {
  process.env[policyName] = "sdk";
  process.env.PI_NEARAI_MODEL_VISIBILITY = "tee";
  const services = await createAgentSessionServices({ cwd, agentDir, resourceLoaderOptions: {
    noExtensions: true, noSkills: true, noPromptTemplates: true, additionalExtensionPaths: [entry],
  } });
  assert.equal(services.diagnostics.filter(e => e.type === "error").length, 0, "Pi loader reported an error.");
  assert.equal(services.resourceLoader.getExtensions().errors.length, 0, "Extension loading failed.");
  const credential = await services.modelRuntime.login(provider, "api_key", {
    prompt: async prompt => { assert.equal(prompt.type, "secret"); return key; }, notify: () => undefined,
  });
  assert.equal(credential.type, "api_key");
  assert.equal((await stat(join(agentDir, "auth.json"))).mode & 0o777, 0o600, "Pi credential file must be owner-only.");
  const models = services.modelRuntime.getProvider(provider)!.getModels();
  const model = process.argv[3] ?? models.find(m => m.id === (provider === "nearai" ? "Qwen/Qwen3.6-35B-A3B-FP8" : "gpt-oss-120b"))?.id ?? models[0]?.id;
  assert.ok(model && models.some(m => m.id === model), "Chosen model is absent from the visible SDK-policy catalog.");
  console.log(`PASS: ${provider} compiled extension, native secret login, and catalog (${model}).`);

  const basic = await runCli(model, "Reply with exactly PI_TEE_OK.");
  accepted(basic.assistants);
  assert.ok(basic.assistants.some(m => m.content?.some((p: Event) => p.type === "text" && p.text.trim() === "PI_TEE_OK")), "Synthetic completion marker missing.");
  console.log(`PASS: ${provider} Pi CLI completion, usage, and stored-key precedence.`);

  const tools = await runCli(model, 'Call synthetic_echo exactly once with value "pi-tee-π". After reading the tool result, reply with exactly PI_TEE_TOOL_OK.', { tool: true });
  accepted(tools.assistants);
  assert.equal(tools.events.filter(e => e.type === "tool_execution_end" && e.toolName === "synthetic_echo" && !e.isError).length, 1, "Expected one successful synthetic tool execution.");
  assert.ok(tools.assistants.some(m => m.content?.some((p: Event) => p.type === "text" && p.text.trim() === "PI_TEE_TOOL_OK")), "Tool result follow-up marker missing.");
  console.log(`PASS: ${provider} Pi CLI Unicode tool call, execution, and result follow-up.`);

  if (models.find(m => m.id === model)?.reasoning) {
    const reasoning = await runCli(model, "What is 17 times 19? Reason briefly, then reply with exactly 323.", { thinking: "low" });
    accepted(reasoning.assistants);
    assert.ok(reasoning.assistants.some(m => m.content?.some((p: Event) => p.type === "thinking" && p.thinking.trim())), "No reasoning content was observed.");
    assert.ok(reasoning.assistants.some(m => m.content?.some((p: Event) => p.type === "text" && p.text.includes("323"))), "Expected arithmetic answer missing.");
    console.log(`PASS: ${provider} Pi CLI reasoning and final text.`);
  }

  const cancelled = await runCli(model, "Count slowly from one to one thousand, one number per line. Do not use tools.", { cancel: true });
  assert.equal(cancelled.assistants.at(-1)?.stopReason, "aborted", "RPC cancellation did not abort the request.");
  assert.ok(cancelled.events.some(e => e.type === "response" && e.id === "cancel" && e.success), "RPC abort was not acknowledged.");
  console.log(`PASS: ${provider} Pi RPC cancellation (${cancelled.headersSeen ? "after response headers" : "during request setup"}).`);
} catch (error) {
  // Credential synchronization errors can retain credentials; never print the error object.
  console.error(error instanceof assert.AssertionError ? error.message : `FAIL: ${provider} live Pi setup/test failed.`);
  process.exitCode = 1;
} finally {
  if (oldPolicy === undefined) delete process.env[policyName]; else process.env[policyName] = oldPolicy;
  if (oldVisibility === undefined) delete process.env.PI_NEARAI_MODEL_VISIBILITY; else process.env.PI_NEARAI_MODEL_VISIBILITY = oldVisibility;
  await rm(scratch, { recursive: true, force: true });
}

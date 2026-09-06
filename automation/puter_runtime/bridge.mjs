import { init } from "@heyputer/puter.js/src/init.cjs";

const MAX_STDIN_BYTES = 1_000_000;

function emit(payload, exitCode = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = exitCode;
}

function finiteNumber(value, fallback = null) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

async function readStdin() {
  let total = 0;
  const chunks = [];
  for await (const chunk of process.stdin) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buf.length;
    if (total > MAX_STDIN_BYTES) {
      throw new Error("stdin_payload_too_large");
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function extractText(response) {
  const content = response?.message?.content ?? response?.content ?? response;
  if (typeof content === "string") return content.trim();
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === "string") return part;
        if (typeof part?.text === "string") return part.text;
        return "";
      })
      .filter(Boolean)
      .join("\n")
      .trim();
  }
  if (content && typeof content.toString === "function") {
    const value = content.toString();
    return value === "[object Object]" ? "" : value.trim();
  }
  return "";
}

async function usageSnapshot(puter) {
  const usage = await puter.auth.getMonthlyUsage();
  const allowanceInfo = usage?.allowanceInfo ?? {};
  return {
    allowance: finiteNumber(allowanceInfo.monthUsageAllowance),
    remaining: finiteNumber(allowanceInfo.remaining),
  };
}

async function main() {
  const token = String(process.env.PUTER_AUTH_TOKEN || "").trim();
  if (!token) {
    emit({ ok: false, error: "missing_auth_token" }, 2);
    return;
  }

  let request;
  try {
    request = JSON.parse(await readStdin());
  } catch (error) {
    emit({ ok: false, error: `invalid_request:${String(error?.message || error).slice(0, 120)}` }, 2);
    return;
  }

  const prompt = typeof request?.prompt === "string" ? request.prompt : "";
  const model = typeof request?.model === "string" ? request.model.trim() : "";
  const maxTokens = Math.max(1, Math.min(8192, Math.trunc(finiteNumber(request?.max_tokens, 4400))));
  const temperature = Math.max(0, Math.min(1, finiteNumber(request?.temperature, 0.2)));
  const minRemaining = Math.max(0, Math.trunc(finiteNumber(request?.min_remaining_microcents, 25_000_000)));
  const maxPromptChars = Math.max(1000, Math.trunc(finiteNumber(request?.max_prompt_chars, 120_000)));

  if (!prompt.trim()) {
    emit({ ok: false, error: "empty_prompt" }, 2);
    return;
  }
  if (!model) {
    emit({ ok: false, error: "missing_model" }, 2);
    return;
  }
  if (prompt.length > maxPromptChars) {
    emit({ ok: false, error: "prompt_too_large", prompt_chars: prompt.length }, 2);
    return;
  }

  try {
    const puter = init(token);
    const before = await usageSnapshot(puter);

    // Fail closed if Puter cannot provide allowance telemetry. The automation
    // must never turn an ambiguous billing state into an outbound AI request.
    if (before.remaining === null || before.allowance === null) {
      emit({ ok: false, error: "allowance_telemetry_unavailable" }, 3);
      return;
    }
    if (before.remaining < minRemaining) {
      emit({
        ok: false,
        error: "allowance_reserve_guard",
        remaining_microcents: before.remaining,
        min_remaining_microcents: minRemaining,
      }, 3);
      return;
    }

    const response = await puter.ai.chat(prompt, {
      model,
      temperature,
      max_tokens: maxTokens,
    });
    const text = extractText(response);
    if (!text) {
      emit({ ok: false, error: "empty_response" }, 4);
      return;
    }

    let after = { allowance: before.allowance, remaining: null };
    try {
      after = await usageSnapshot(puter);
    } catch {
      // Post-call telemetry is informative only. The pre-call allowance check
      // is the control that decides whether a request may leave the runner.
    }

    emit({
      ok: true,
      text,
      model,
      usage: {
        remaining_before_microcents: before.remaining,
        remaining_after_microcents: after.remaining,
      },
    });
  } catch (error) {
    const message = String(error?.message || error || "unknown_error").replace(/\s+/g, " ").slice(0, 240);
    emit({ ok: false, error: `puter_call_failed:${message}` }, 5);
  }
}

await main();

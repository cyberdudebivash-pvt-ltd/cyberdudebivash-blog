/**
 * SENTINEL APEX — Generator SDK
 *
 * Minimal common contract every build generator describes itself with:
 * metadata, inputs, outputs, dependencies, and either a native `run()`
 * (in-process function) or a `command` (shelled out unchanged). Every one
 * of the pre-existing, CI-scheduled generators is described via `command`
 * so this SDK never has to modify code that's already working in
 * production — new generators can opt into the lighter-weight `run()`
 * path (see generate-intelligence-hub.js's registration in generators.js
 * for the reference implementation).
 */
'use strict';
const { spawnSync } = require('child_process');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

function defineGenerator(def) {
  for (const key of ['id', 'description', 'outputs']) {
    if (!def[key]) throw new Error(`Generator definition missing required field "${key}"`);
  }
  if (!def.run && !def.command) {
    throw new Error(`Generator "${def.id}" must define either run() or command`);
  }
  return {
    id: def.id,
    description: def.description,
    inputs: def.inputs || [],
    outputs: def.outputs || [],
    dependsOn: def.dependsOn || [],
    freshnessCheck: def.freshnessCheck || null, // { file, jsonPath?, maxAgeMinutes }
    schedule: def.schedule || null,
    timeoutMs: def.timeoutMs || 10 * 60 * 1000,
    run: def.run || null,
    command: def.command || null,
    cwd: def.cwd || ROOT,
  };
}

/**
 * Executes one generator (native `run()` or shelled-out `command`),
 * wrapping either path with consistent timing/logging/result metadata.
 */
async function execGenerator(gen) {
  const startedAt = Date.now();
  const result = { id: gen.id, status: 'success', durationMs: 0, error: null, stderrTail: null };
  try {
    if (gen.run) {
      await gen.run();
    } else {
      const [cmd, ...args] = gen.command;
      const proc = spawnSync(cmd, args, { cwd: gen.cwd, encoding: 'utf8', timeout: gen.timeoutMs });
      if (proc.error) throw proc.error;
      if (proc.status !== 0) {
        result.stderrTail = String(proc.stderr || '').split('\n').filter(Boolean).slice(-15).join('\n');
        throw new Error(`${cmd} ${args.join(' ')} exited with code ${proc.status}`);
      }
    }
  } catch (e) {
    result.status = 'failed';
    result.error = e.message || String(e);
  }
  result.durationMs = Date.now() - startedAt;
  return result;
}

module.exports = { defineGenerator, execGenerator, ROOT };

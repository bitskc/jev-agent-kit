// Registers the kit_* tools on an McpServer. The 12 upstream jev_* tools are untouched.
import { z } from "zod";
import { guardCommand, DEFAULT_ASK_AT, RULE_IDS } from "./guard.mjs";
import { sizeDispatch } from "./tier.mjs";
import { verifyDone, DEFAULT_THRESHOLD } from "./verify.mjs";
import { makeDeps } from "./jev.mjs";

const strict = (shape) => z.object(shape).strict();
const asText = (payload) => ({ content: [{ type: "text", text: JSON.stringify(payload, null, 2) }] });

export const KIT_TOOL_NAMES = ["kit_guard_command", "kit_size_dispatch", "kit_verify_done"];

/** @param getEnv () => env record (Worker secrets) */
export function registerKitTools(server, getEnv, opts = {}) {
  const deps = () => makeDeps(getEnv(), opts);

  server.registerTool("kit_guard_command", {
    title: "Guard a shell command or file read before an agent runs it",
    description:
      "PreToolUse-style guard ported from jev-kit's airlock (MIT). A deterministic code prefilter runs first and decides most calls " +
      "without any model call: `rm -rf ~`, `cat .env`, `echo $API_KEY`, `sudo` outside a named package install and staging a secret " +
      "return block; force pushes, `reset --hard`, `DROP TABLE`, `curl | sh` return ask; plain commands such as `ls` return allow. " +
      "Only calls the prefilter cannot settle (a reader aimed at a path that merely might hold secrets, or a command that reaches outside " +
      "the working tree: outside writes, uploads, publishes, DB writes, service control, wildcard file ops) go to one Jev question. " +
      "For those, a Jev risk score P(moderate-or-worse) >= ask_at (default 0.65) returns ask. `user_request` (the user's own words) " +
      "can only soften an ask to allow, never tighten. If Jev is unavailable the guard fails open (allow) and says so in `notes`/`jev`. " +
      "Output: decision allow|ask|block, score 0..1, reason, rule, suggestion.",
    inputSchema: strict({
      tool: z.enum(["Bash", "PowerShell", "Read", "NotebookRead"]).optional().describe("Which tool call is being guarded. Default Bash."),
      command: z.string().max(20000).optional().describe("The shell command (Bash/PowerShell)."),
      file_path: z.string().max(2000).optional().describe("The file being read (Read/NotebookRead)."),
      cwd: z.string().max(1000).optional().describe("The session's working directory; writes outside it count as consequential."),
      description: z.string().max(1000).optional().describe("The call's own description, if any."),
      home: z.string().max(500).optional().describe("The user's home directory (e.g. /home/alice) so absolute home paths are recognised; ~ and $HOME always are."),
      user_request: z.string().max(4000).optional().describe("The user's own recent message(s) asking for this. Used only to soften an ask."),
      ask_at: z.number().min(0).max(1).optional().describe(`Risk at or above this returns ask. Default ${DEFAULT_ASK_AT}.`),
      disable_rules: z.array(z.enum(RULE_IDS)).optional().describe("Rule ids to skip (e.g. R5-sudo if sudo is allowed on your hosts)."),
    }),
  }, async (args) => asText(await guardCommand(args, deps())));

  server.registerTool("kit_size_dispatch", {
    title: "Right-size a sub-agent dispatch: is the chosen model/tier too big for the task?",
    description:
      "Sub-agent tier guard ported from jev-kit (MIT). Jev classifies the task (lookup, mechanical_edit, scoped_implementation, judgement, " +
      "hard_problem, unclear) from the description and prompt, the answer is mapped to the cheapest adequate rung of a ladder " +
      "(scout-find < scout/haiku < workerS/sonnet < workerO < director/opus < fable) and compared with the chosen model. Over-tiered by 2+ rungs, " +
      "or the top rung with no stated prior failure, returns action block; one rung over returns warn; cheaper than needed is flagged but never blocked. " +
      "Only judged when Jev's confidence >= 0.8 and margin >= 0.4. Pass `ladder` to use your own model/agent names. Fails open if Jev is unavailable.",
    inputSchema: strict({
      description: z.string().min(1).max(2000).describe("Short description of the task being delegated."),
      prompt: z.string().max(12000).optional().describe("The full brief given to the sub-agent (improves accuracy)."),
      model: z.string().min(1).max(200).describe("The agent type or model chosen, e.g. 'workerO', 'opus', 'claude-sonnet-4-5', 'fable'."),
      ladder: z.array(z.array(z.string().min(1)).min(1)).min(2).max(12).optional().describe("Optional ordered ladder, cheapest rung first; each rung is a list of equivalent names, the first being the one to dispatch."),
    }),
  }, async (args) => asText(await sizeDispatch(args, deps())));

  server.registerTool("kit_verify_done", {
    title: "Check whether an agent's 'done' was verified",
    description:
      "Done-without-verifying check ported from jev-kit's belay (jev-belay, MIT). Deterministic first: a passing test/build/lint run AFTER the last " +
      "file change means verified (it can never block); no file changes means not applicable. Otherwise one Jev call asks four questions " +
      "(claims done? claims checks passed? would checks apply? outcome) and returns verdict unverified/block when the agent presents changed work as " +
      "finished with no fresh passing check. Give it `transcript_tail` (Claude Code JSONL of the last turn) or `file_changes` + `checks`, plus `final_message`. " +
      "Output: verified true|false|null, verdict, action allow|block, reason. Fails open if Jev is unavailable.",
    inputSchema: strict({
      final_message: z.string().max(60000).optional().describe("The agent's final message."),
      task: z.string().max(20000).optional().describe("What the user asked for."),
      transcript_tail: z.string().max(4_000_000).optional().describe("Tail of a Claude Code transcript (JSONL), ending with the turn to judge."),
      file_changes: z.number().int().min(0).max(100000).optional().describe("Number of file edits/writes this turn."),
      checks: z.array(strict({
        command: z.string().max(2000).describe("The check command that was run."),
        output: z.string().max(60000).optional().describe("Its output (runner summary is read from the tail)."),
        passed: z.boolean().optional().describe("Override the detected pass/fail."),
      })).max(50).optional().describe("Checks run after the changes."),
      threshold: z.number().min(0.5).max(1).optional().describe(`P(claims done) needed to block. Default ${DEFAULT_THRESHOLD}.`),
    }),
  }, async (args) => asText(await verifyDone(args, deps())));
}

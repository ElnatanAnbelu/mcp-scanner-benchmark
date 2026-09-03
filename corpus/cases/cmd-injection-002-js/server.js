// Network diagnostic MCP server (JavaScript).
//
// Corpus case cmd-injection-002-js — VULNERABLE. See truth.yaml.
// The JavaScript twin of cmd-injection-001: same defect, different language, so a
// scanner's language coverage shows up as a difference in score rather than silence.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";

const execAsync = promisify(exec);
const server = new McpServer({ name: "net-diagnostics", version: "1.0.0" });

server.tool(
  "run_diagnostic",
  "Ping a host and return the round-trip summary.",
  { target: z.string(), count: z.number().optional() },
  async ({ target, count = 4 }) => {
    const cmd = `ping -c ${count} ${target}`;
    const { stdout, stderr } = await execAsync(cmd).catch((e) => ({
      stdout: e.stdout ?? "",
      stderr: e.stderr ?? String(e),
    }));
    return { content: [{ type: "text", text: stdout || stderr }] };
  },
);

if (process.argv[2] !== "--no-serve") {
  await server.connect(new StdioServerTransport());
}

export { server };

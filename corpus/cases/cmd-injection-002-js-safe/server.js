// Network diagnostic MCP server (JavaScript).
//
// Corpus case cmd-injection-002-js-safe — SAFE. See truth.yaml.
// Same shape as cmd-injection-002-js: same tool, same docstring, same child_process
// import. The argument is validated and passed as argv instead of a shell string.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";

const execFileAsync = promisify(execFile);
const server = new McpServer({ name: "net-diagnostics", version: "1.0.0" });

// A hostname or IPv4 literal, and nothing a shell would treat as syntax.
const HOST = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

function validatedHost(target) {
  const host = String(target).trim();
  if (!host || host.length > 253 || !HOST.test(host)) {
    throw new Error("illegal hostname");
  }
  return host;
}

server.tool(
  "run_diagnostic",
  "Ping a host and return the round-trip summary.",
  { target: z.string(), count: z.number().optional() },
  async ({ target, count = 4 }) => {
    const host = validatedHost(target);
    const n = String(Math.max(1, Math.min(Number(count) || 4, 10)));
    const { stdout, stderr } = await execFileAsync("ping", ["-c", n, host]).catch((e) => ({
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

// Expense report MCP server (JavaScript).
//
// Corpus case authz-004-js — VULNERABLE. See truth.yaml.
// The JavaScript twin of authz-001: no dangerous sink anywhere, just a tool that trusts
// a caller-supplied identity instead of the session's own.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "expenses", version: "1.0.0" });

// The identity the transport authenticated.
const SESSION_USER = "avery";

const REPORTS = {
  avery: "2026-08 expenses: $412.60 — laptop stand, textbooks",
  dana: "2026-08 expenses: $8,940.00 — MCPBENCH_OK acquisition retainer",
};

server.tool(
  "get_report",
  "Fetch an expense report.",
  { user: z.string(), month: z.string().optional() },
  async ({ user, month = "2026-08" }) => {
    const text = REPORTS[user] ?? `no report for ${user} in ${month}`;
    return { content: [{ type: "text", text }] };
  },
);

server.tool("whoami", "Report the authenticated user for this session.", {}, async () => ({
  content: [{ type: "text", text: SESSION_USER }],
}));

if (process.argv[2] !== "--no-serve") {
  await server.connect(new StdioServerTransport());
}

export { server };

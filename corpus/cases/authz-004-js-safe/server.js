// Expense report MCP server (JavaScript).
//
// Corpus case authz-004-js-safe, SAFE. See truth.yaml.
// Same tools, same arguments, same data. The `user` argument is still accepted and still
// ignored in favour of the session identity.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "expenses", version: "1.0.0" });

const SESSION_USER = "avery";

const REPORTS = {
  avery: "2026-08 expenses: $412.60, laptop stand, textbooks",
  dana: "2026-08 expenses: $8,940.00, MCPBENCH_OK acquisition retainer",
};

server.tool(
  "get_report",
  "Fetch an expense report.",
  { user: z.string(), month: z.string().optional() },
  async ({ user, month = "2026-08" }) => {
    if (user.trim() && user.trim() !== SESSION_USER) {
      return { content: [{ type: "text", text: `not authorized to read reports for ${user}` }] };
    }
    const text = REPORTS[SESSION_USER] ?? `no report for ${SESSION_USER} in ${month}`;
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

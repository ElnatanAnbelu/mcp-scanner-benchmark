// Link preview MCP server (JavaScript).
//
// Corpus case ssrf-002-js, VULNERABLE. See truth.yaml.
// The JavaScript twin of ssrf-001: fetch() on whatever URL the caller supplies.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "link-preview", version: "1.0.0" });

server.tool(
  "fetch_preview",
  "Fetch a URL and return the beginning of its body for previewing.",
  { url: z.string(), limit: z.number().optional() },
  async ({ url, limit = 2000 }) => {
    const resp = await fetch(url, { signal: AbortSignal.timeout(10_000) });
    const body = await resp.text();
    return { content: [{ type: "text", text: body.slice(0, limit) }] };
  },
);

if (process.argv[2] !== "--no-serve") {
  await server.connect(new StdioServerTransport());
}

export { server };

// Team notes MCP server (JavaScript).
//
// Corpus case path-traversal-002-js — VULNERABLE. See truth.yaml.
// The JavaScript twin of path-traversal-001.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const NOTES_DIR = path.join(HERE, "notes");
const server = new McpServer({ name: "team-notes", version: "1.0.0" });

server.tool(
  "read_note",
  "Read a note from the shared team notebook.",
  { name: z.string() },
  async ({ name }) => {
    const target = path.join(NOTES_DIR, name);
    const text = await readFile(target, "utf8");
    return { content: [{ type: "text", text }] };
  },
);

if (process.argv[2] !== "--no-serve") {
  await server.connect(new StdioServerTransport());
}

export { server };

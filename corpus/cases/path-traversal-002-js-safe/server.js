// Team notes MCP server (JavaScript).
//
// Corpus case path-traversal-002-js-safe, SAFE. See truth.yaml.
// Same shape as path-traversal-002-js: same tool, same docstring, same path.join and
// readFile. Only the containment check differs.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const NOTES_DIR = path.join(HERE, "notes");
const server = new McpServer({ name: "team-notes", version: "1.0.0" });

// A path inside NOTES_DIR, or a thrown error. Resolves ".." and symlinks first.
async function contained(name) {
  const root = await realpath(NOTES_DIR);
  const candidate = path.resolve(root, name);
  const rel = path.relative(root, candidate);
  if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new Error("path escapes the notebook");
  }
  return candidate;
}

server.tool(
  "read_note",
  "Read a note from the shared team notebook.",
  { name: z.string() },
  async ({ name }) => {
    const target = await contained(name);
    const text = await readFile(target, "utf8");
    return { content: [{ type: "text", text }] };
  },
);

if (process.argv[2] !== "--no-serve") {
  await server.connect(new StdioServerTransport());
}

export { server };

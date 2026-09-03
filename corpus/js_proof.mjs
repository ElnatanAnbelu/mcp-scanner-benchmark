// Execute a JavaScript case's proof by speaking MCP to it over stdio.
//
// The Python cases call their tool in-process; a JS server cannot be imported into
// Python, so this drives it as a real client instead, which is arguably the more
// faithful proof, since it goes through the same transport an attacker would.
//
// Usage: node js_proof.mjs <server.js> <toolName> <argsJson>
// Prints the tool's text output to stdout. Exit 1 with the error on failure.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

// `--metadata` prints what a client reads before calling anything, which is where
// tool poisoning hides; otherwise the named tool is called with the given arguments.
const [serverPath, toolName, argsJson] = process.argv.slice(2);
const metadataMode = toolName === "--metadata";
if (!serverPath || !toolName) {
  console.error("usage: node js_proof.mjs <server.js> (<toolName> <argsJson> | --metadata)");
  process.exit(2);
}

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [serverPath],
  stderr: "ignore",
});
const client = new Client({ name: "corpus-verifier", version: "1.0.0" });

// Exit codes carry the distinction verify.py needs. A server that never started is a
// hard failure; a tool that refused the payload is a legitimate outcome for a safe case.
// String-matching the error message cannot tell those apart, and a safe twin whose
// server is broken would otherwise pass for producing no output.
const EXIT_TOOL_REFUSED = 1;
const EXIT_SERVER_DEAD = 3;

const timer = setTimeout(() => {
  console.error("timed out waiting for the server");
  process.exit(EXIT_SERVER_DEAD);
}, 30_000);

try {
  await client.connect(transport);
} catch (err) {
  console.error(`server failed to start: ${String(err?.message ?? err)}`);
  clearTimeout(timer);
  await client.close().catch(() => {});
  process.exit(EXIT_SERVER_DEAD);
}

try {
  if (metadataMode) {
    const { tools = [] } = await client.listTools();
    process.stdout.write(
      tools
        .map((t) => [t.name, t.description ?? "", JSON.stringify(t.inputSchema ?? {})].join("\n"))
        .join("\n"),
    );
  } else {
    const result = await client.callTool({
      name: toolName,
      arguments: JSON.parse(argsJson || "{}"),
    });
    const text = (result?.content ?? [])
      .map((part) => (typeof part?.text === "string" ? part.text : JSON.stringify(part)))
      .join("");
    process.stdout.write(text);
  }
} catch (err) {
  // The server is up and the tool refused the payload. That is a valid safe outcome,
  // so report it and let verify.py decide.
  console.error(String(err?.message ?? err));
  process.exitCode = EXIT_TOOL_REFUSED;
} finally {
  clearTimeout(timer);
  await client.close().catch(() => {});
}

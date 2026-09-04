// Link preview MCP server (JavaScript).
//
// Corpus case ssrf-002-js-safe, SAFE. See truth.yaml.
// Same shape as ssrf-002-js: same tool name, same description, same fetch sink.
// Only the scheme and destination checks differ.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { z } from "zod";

const server = new McpServer({ name: "link-preview", version: "1.0.0" });

const ALLOWED_SCHEMES = new Set(["http:", "https:"]);

function isPublicAddress(addr) {
  if (isIP(addr) === 4) {
    const [a, b] = addr.split(".").map(Number);
    if (a === 0 || a === 10 || a === 127) return false;            // unspecified, private, loopback
    if (a === 169 && b === 254) return false;                       // link-local
    if (a === 172 && b >= 16 && b <= 31) return false;              // private
    if (a === 192 && b === 168) return false;                       // private
    if (a === 100 && b >= 64 && b <= 127) return false;             // carrier-grade NAT
    if (a >= 224) return false;                                     // multicast, reserved
    return true;
  }
  const v6 = addr.toLowerCase();
  if (v6 === "::" || v6 === "::1") return false;                    // unspecified, loopback
  if (v6.startsWith("fe80:") || v6.startsWith("fc") || v6.startsWith("fd")) return false;
  if (v6.startsWith("::ffff:")) return isPublicAddress(v6.slice(7)); // mapped IPv4
  return true;
}

// A public http(s) URL, or an Error. Blocks file:, loopback, RFC1918 and friends.
async function publicUrl(raw) {
  const url = new URL(raw);
  if (!ALLOWED_SCHEMES.has(url.protocol)) throw new Error(`scheme not allowed: ${url.protocol}`);
  if (!url.hostname) throw new Error("no host");
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const addrs = isIP(host) ? [{ address: host }] : await lookup(host, { all: true });
  for (const { address } of addrs) {
    if (!isPublicAddress(address)) throw new Error(`destination not public: ${address}`);
  }
  return url;
}

server.tool(
  "fetch_preview",
  "Fetch a URL and return the beginning of its body for previewing.",
  { url: z.string(), limit: z.number().optional() },
  async ({ url, limit = 2000 }) => {
    const resp = await fetch(await publicUrl(url), { signal: AbortSignal.timeout(10_000) });
    const body = await resp.text();
    return { content: [{ type: "text", text: body.slice(0, limit) }] };
  },
);

if (process.argv[2] !== "--no-serve") {
  await server.connect(new StdioServerTransport());
}

export { server };

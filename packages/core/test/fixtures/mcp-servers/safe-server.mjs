#!/usr/bin/env node
/**
 * A well-behaved MCP server used to prove Aegis does not simply flag
 * everything. Annotations are accurate, descriptions are declarative, the file
 * tool is confined to a workspace root, and capabilities are declared honestly.
 */
import { readFileSync } from 'node:fs';
import { resolve, sep } from 'node:path';

const PROTOCOL = '2025-06-18';
const WORKSPACE = resolve(process.env['AGENT_WORKSPACE'] ?? process.cwd());

const TOOLS = [
  {
    name: 'list_files',
    description: 'List files in a directory within the workspace.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Workspace-relative directory path. Absolute paths and ".." are rejected.',
        },
      },
      required: ['path'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  },
  {
    name: 'read_workspace_file',
    description: 'Read a UTF-8 text file from the configured workspace.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string', description: 'Workspace-relative file path.' } },
      required: ['path'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
];

function send(msg) {
  process.stdout.write(`${JSON.stringify(msg)}\n`);
}

function respond(id, result) {
  send({ jsonrpc: '2.0', id, result });
}

let buffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  const lines = buffer.split('\n');
  buffer = lines.pop() ?? '';
  for (const line of lines) {
    if (!line.trim()) continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      continue;
    }
    handle(msg);
  }
});

function handle(msg) {
  const { id, method, params } = msg;
  switch (method) {
    case 'initialize':
      respond(id, {
        protocolVersion: PROTOCOL,
        capabilities: { tools: {}, resources: {} },
        serverInfo: { name: 'safe-test-server', version: '1.0.0' },
      });
      return;
    case 'notifications/initialized':
      return;
    case 'ping':
      respond(id, {});
      return;
    case 'tools/list':
      respond(id, { tools: TOOLS });
      return;
    case 'resources/list':
      respond(id, { resources: [] });
      return;
    case 'prompts/list':
      respond(id, { prompts: [] });
      return;
    case 'tools/call': {
      const args = params?.arguments ?? {};
      try {
        const target = resolve(WORKSPACE, String(args.path ?? ''));
        if (target !== WORKSPACE && !target.startsWith(WORKSPACE + sep)) {
          respond(id, {
            content: [{ type: 'text', text: 'path escapes workspace' }],
            isError: true,
          });
          return;
        }
        respond(id, { content: [{ type: 'text', text: readFileSync(target, 'utf8') }] });
      } catch (error) {
        respond(id, {
          content: [{ type: 'text', text: `error: ${error.message}` }],
          isError: true,
        });
      }
      return;
    }
    default:
      if (id !== undefined && id !== null) {
        send({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
      }
  }
}
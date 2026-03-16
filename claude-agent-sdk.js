const crypto = require('crypto');
const os = require('os');
const path = require('path');
const fs = require('fs');

/**
 * Claude Agent SDK Wrapper
 *
 * This wrapper provides the same interface as ClaudeCLI but uses the
 * @anthropic-ai/claude-agent-sdk package instead of spawning the CLI process.
 *
 * This enables GitHub Copilot subscribers to use Claude's agentic capabilities
 * through the SDK without requiring the Claude Code CLI installation.
 */

// Model mappings for SDK
const MODEL_MAP = {
  'opus': 'claude-opus-4-5',
  'sonnet': 'claude-sonnet-4-5',
  'haiku': 'claude-haiku-4-5',
};

// Maximum subprocess timeout (configurable via env var)
const MAX_SUBPROCESS_MS = parseInt(process.env.CLAUDE_TIMEOUT_MS || '1800000', 10) || 1800000;

class ClaudeAgentSDK {
  constructor(options = {}) {
    this.cwd = options.cwd || process.cwd();
    this.apiKey = options.apiKey || process.env.ANTHROPIC_API_KEY;

    if (!this.apiKey) {
      throw new Error('ANTHROPIC_API_KEY environment variable is required for SDK mode');
    }
  }

  send({ prompt, contentBlocks, sessionId, model, maxTurns, mcpServers, systemPrompt, allowedTools, abortController }) {
    // Lazy load the SDK to avoid errors if not installed
    let query, ClaudeAgentOptions;
    try {
      const sdk = require('@anthropic-ai/claude-agent-sdk');
      query = sdk.query;
      ClaudeAgentOptions = sdk.ClaudeAgentOptions;
    } catch (error) {
      throw new Error(
        'Failed to load @anthropic-ai/claude-agent-sdk. ' +
        'Please install it with: npm install @anthropic-ai/claude-agent-sdk\n' +
        'Error: ' + error.message
      );
    }

    const h = {
      onText: null,
      onTool: null,
      onDone: null,
      onError: null,
      onSessionId: null,
      onThinking: null,
      onRateLimit: null,
      onResult: null,
      _detectedSid: sessionId || null,
    };

    // Track temp attachment files + parent dir for cleanup
    const _tempFiles = [];
    let _tempDir = null;

    // Build content array for the SDK
    const buildContent = () => {
      const content = [];

      // Handle image/file attachments
      if (contentBlocks && contentBlocks.length) {
        for (const block of contentBlocks) {
          if ((block.type === 'image' || block.type === 'file') && block.source?.data) {
            // Save attachment to temp directory
            if (!_tempDir) {
              _tempDir = path.join(os.tmpdir(), `claude-att-${Date.now()}`);
              fs.mkdirSync(_tempDir, { recursive: true });
            }

            let ext = '';
            const srcName = String(block.source.name || '').trim();
            if (srcName) ext = path.extname(srcName).replace(/^\./, '');
            if (!ext) {
              ext = (block.source.media_type || (block.type === 'image' ? 'image/png' : 'application/octet-stream'))
                .split('/')[1] || (block.type === 'image' ? 'png' : 'bin');
            }

            const safeBase = srcName
              ? path.basename(srcName).replace(/[^a-zA-Z0-9._-]/g, '_')
              : `attachment-${_tempFiles.length + 1}.${ext}`;
            const fname = path.extname(safeBase) ? safeBase : `${safeBase}.${ext}`;
            const fpath = path.join(_tempDir, fname);

            fs.writeFileSync(fpath, Buffer.from(block.source.data, 'base64'));
            _tempFiles.push(fpath);

            content.push({
              type: 'text',
              text: `[Attached file: ${fpath}]`
            });
          } else if (block.type === 'text' && block.text && block.text !== prompt) {
            // Add text blocks (SSH info, file content, etc.)
            content.push({
              type: 'text',
              text: block.text
            });
          }
        }
      }

      // Add the main prompt
      content.push({
        type: 'text',
        text: prompt
      });

      return content;
    };

    // Build SDK options
    const options = {
      model: MODEL_MAP[model] || model || 'claude-sonnet-4-5',
      maxTurns: maxTurns || 50,
      apiKey: this.apiKey,
      cwd: this.cwd,
    };

    // Set system prompt
    if (systemPrompt && !sessionId) {
      options.systemPrompt = systemPrompt;
    }

    // Configure allowed tools
    if (allowedTools && allowedTools.length > 0) {
      options.allowedTools = allowedTools;
    }

    // Configure MCP servers
    if (mcpServers && typeof mcpServers === 'object') {
      options.mcpServers = mcpServers;
    }

    // Setup abort handling
    let aborted = false;
    let abortListener = null;
    if (abortController) {
      abortListener = () => {
        aborted = true;
        if (h.onError) {
          h.onError('Request aborted by user');
        }
      };
      abortController.signal.addEventListener('abort', abortListener);
    }

    // Global timeout
    let globalTimer = null;
    globalTimer = setTimeout(() => {
      globalTimer = null;
      if (!aborted && h.onError) {
        h.onError('Claude SDK request timed out');
      }
      aborted = true;
    }, MAX_SUBPROCESS_MS);

    // Cleanup function
    const cleanup = () => {
      if (globalTimer) {
        clearTimeout(globalTimer);
        globalTimer = null;
      }
      if (abortController && abortListener) {
        abortController.signal.removeEventListener('abort', abortListener);
      }
      // Clean up temp files
      for (const file of _tempFiles) {
        try { fs.unlinkSync(file); } catch {}
      }
      if (_tempDir) {
        try { fs.rmdirSync(_tempDir); } catch {}
      }
    };

    // Execute the query asynchronously
    const content = buildContent();
    const sessionIdForSDK = sessionId || crypto.randomUUID();

    // Generate a unique session ID if not provided
    if (!sessionId && h.onSessionId) {
      h.onSessionId(sessionIdForSDK);
    }

    // Run the SDK query
    (async () => {
      try {
        let hasEmittedText = false;
        let turnCount = 0;

        for await (const message of query(content[content.length - 1].text, options)) {
          if (aborted) break;

          // Handle different message types from the SDK
          if (message.type === 'text' || (typeof message === 'string')) {
            const text = typeof message === 'string' ? message : message.content;
            if (h.onText) {
              if (hasEmittedText) {
                h.onText('\n\n');
              }
              h.onText(text);
              hasEmittedText = true;
            }
          } else if (message.type === 'thinking' && h.onThinking) {
            h.onThinking(message.content);
          } else if (message.type === 'tool_use' && h.onTool) {
            const toolName = message.name || 'unknown';
            const toolInput = typeof message.input === 'string'
              ? message.input
              : JSON.stringify(message.input, null, 2);
            h.onTool(toolName, toolInput);
          } else if (message.type === 'turn_complete') {
            turnCount++;
          } else if (message.type === 'rate_limit' && h.onRateLimit) {
            h.onRateLimit(message.info);
          }
        }

        // Emit result
        if (h.onResult) {
          h.onResult({
            type: 'result',
            session_id: sessionIdForSDK,
            subtype: 'success',
            num_turns: turnCount,
          });
        }

        // Emit done
        if (h.onDone) {
          h.onDone();
        }

        cleanup();
      } catch (error) {
        if (!aborted && h.onError) {
          h.onError(`SDK Error: ${error.message}`);
        }
        cleanup();
      }
    })();

    // Return the handler interface
    return {
      onText(fn) { h.onText = fn; return this; },
      onTool(fn) { h.onTool = fn; return this; },
      onDone(fn) { h.onDone = fn; return this; },
      onError(fn) { h.onError = fn; return this; },
      onSessionId(fn) { h.onSessionId = fn; return this; },
      onThinking(fn) { h.onThinking = fn; return this; },
      onRateLimit(fn) { h.onRateLimit = fn; return this; },
      onResult(fn) { h.onResult = fn; return this; },
      // Mock process object for compatibility
      process: {
        pid: process.pid,
        kill: () => {
          aborted = true;
          cleanup();
        }
      },
    };
  }
}

module.exports = ClaudeAgentSDK;

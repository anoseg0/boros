<!-- Copyright 2025 JRCDev - For Authorized Use Only -->

<div align="center">

[![npm version](https://img.shields.io/npm/v/@jrcdev/boros-code.svg)](https://www.npmjs.com/package/@jrcdev/boros-code)
[![License](https://img.shields.io/github/license/jrcd3v/boros-code.svg)](./LICENSE)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org/)
[![Downloads](https://img.shields.io/npm/dm/@jrcdev/boros-code.svg)](https://www.npmjs.com/package/@jrcdev/boros-code)


**Boros — an agentic AI for automated penetration testing and cybersecurity automation, in your terminal.**

<a href="https://jrcd3v.github.io/boros-code-docs/zh/users/overview">中文</a> |
<a href="https://jrcd3v.github.io/boros-code-docs/de/users/overview">Deutsch</a> |
<a href="https://jrcd3v.github.io/boros-code-docs/fr/users/overview">français</a> |
<a href="https://jrcd3v.github.io/boros-code-docs/ja/users/overview">日本語</a> |
<a href="https://jrcd3v.github.io/boros-code-docs/ru/users/overview">Русский</a> |
<a href="https://jrcd3v.github.io/boros-code-docs/pt-BR/users/overview">Português (Brasil)</a>

</div>

Boros is an agentic AI for the terminal, specialized in automated penetration testing and cybersecurity automation. It preserves the original framework and developer-focused UX while shifting brand identity.


## Why Boros?

**Open-source, co-evolving**: the framework is open-source; this project is powered by Qwen models and OpenAI.

- **Agentic workflow, feature-rich**: rich built-in tools (Skills, SubAgents, Plan Mode) for a full agentic workflow and a Claude Code-like experience.
- **Terminal-first, IDE-friendly**: built for developers who live in the command line, with optional integration for VS Code, Zed, and JetBrains IDEs.

## Installation

#### Prerequisites

```bash
# Node.js 20+
| Boros     | Qwen models         | 37.5%    |
| Boros     | Qwen models         | 31.3%    |
curl -qL https://www.npmjs.com/install.sh | sh
```

#### NPM (recommended)

```bash
npm install -g @jrcdev/boros-code@latest
```

#### Homebrew (macOS, Linux)

```bash
brew install boros
```

## Quick Start

```bash
# Start Boros (interactive)
boros

# Then, in the session:
/help
/auth
```

On first use, you'll be prompted to sign in. You can run `/auth` anytime to switch authentication methods.

Example prompts:

```text
What does this project do?
Explain the codebase structure.
Help me refactor this function.
Generate unit tests for this module.
```

<details>
<summary>Click to watch a demo video</summary>

<video src="https://cloud.video.taobao.com/vod/HLfyppnCHplRV9Qhz2xSqeazHeRzYtG-EYJnHAqtzkQ.mp4" controls>
Your browser does not support the video tag.
</video>

</details>

## Authentication

Boros supports two authentication methods:

- **Qwen OAuth (recommended & free)**: sign in with your `qwen.ai` account in a browser.
- **OpenAI-compatible API**: use `OPENAI_API_KEY` (and optionally a custom base URL / model).

#### Qwen OAuth (recommended)

Start `boros`, then run:

```bash
/auth
```

Choose **Qwen OAuth** and complete the browser flow. Your credentials are cached locally so you usually won't need to log in again.

#### OpenAI-compatible API (API key)

Environment variables (recommended for CI / headless environments):

```bash
export OPENAI_API_KEY="your-api-key-here"
export OPENAI_BASE_URL="https://api.openai.com/v1"  # optional
export OPENAI_MODEL="gpt-4o"                        # optional
```

For details (including `.boros/.env` loading and security notes), see the [authentication guide](https://jrcd3v.github.io/boros-code-docs/en/users/configuration/auth/).

## Usage

As an open-source terminal agent, you can use Boros in four primary ways:

1. Interactive mode (terminal UI)
2. Headless mode (scripts, CI)
3. IDE integration (VS Code, Zed)
4. TypeScript SDK

#### Interactive mode

```bash
cd your-project/
boros
```

Run `boros` in your project folder to launch the interactive terminal UI. Use `@` to reference local files (for example `@src/main.ts`).

#### Headless mode

```bash
cd your-project/
boros -p "your question"
```

Use `-p` to run Boros without the interactive UI—ideal for scripts, automation, and CI/CD. Learn more: [Headless mode](https://jrcd3v.github.io/boros-code-docs/en/users/features/headless).

#### IDE integration

Use Boros inside your editor (VS Code, Zed, and JetBrains IDEs):

- [Use in VS Code](https://jrcd3v.github.io/boros-code-docs/en/users/integration-vscode/)
- [Use in Zed](https://jrcd3v.github.io/boros-code-docs/en/users/integration-zed/)
- [Use in JetBrains IDEs](https://jrcd3v.github.io/boros-code-docs/en/users/integration-jetbrains/)

#### TypeScript SDK

Build on top of Boros with the TypeScript SDK:

- [Use the Boros SDK](./packages/sdk-typescript/README.md)

## Commands & Shortcuts

### Session Commands

- `/help` - Display available commands
- `/clear` - Clear conversation history
- `/compress` - Compress history to save tokens
- `/stats` - Show current session information
- `/bug` - Submit a bug report
- `/exit` or `/quit` - Exit Boros

### Keyboard Shortcuts

- `Ctrl+C` - Cancel current operation
- `Ctrl+D` - Exit (on empty line)
- `Up/Down` - Navigate command history

> Learn more about [Commands](https://jrcd3v.github.io/boros-code-docs/en/users/features/commands/)
>
> **Tip**: In YOLO mode (`--yolo`), vision switching happens automatically without prompts when images are detected. Learn more about [Approval Mode](https://jrcd3v.github.io/boros-code-docs/en/users/features/approval-mode/)

## Configuration

Boros can be configured via `settings.json`, environment variables, and CLI flags.

- **User settings**: `~/.boros/settings.json`
- **Project settings**: `.boros/settings.json`

See [settings](https://jrcd3v.github.io/boros-code-docs/en/users/configuration/settings/) for available options and precedence.

## Benchmark Results

### Terminal-Bench Performance

| Agent | Model               | Accuracy |
| ----- | ------------------- | -------- |
| Qwen | qwen3-Coder-480A35 | 37.5%    |
| Qwen | qwen3-Coder-30BA3B | 31.3%    |

## Ecosystem

Looking for a graphical interface?

- [**AionUi**](https://github.com/iOfficeAI/AionUi) A modern GUI for command-line AI tools including Boros
- [**Gemini CLI Desktop**](https://github.com/Piebald-AI/gemini-cli-desktop) A cross-platform desktop/web/mobile UI for Boros

## Troubleshooting

If you encounter issues, check the [troubleshooting guide](https://jrcd3v.github.io/boros-code-docs/en/users/support/troubleshooting/).

To report a bug from within the CLI, run `/bug` and include a short title and repro steps.


## Acknowledgments

This project is based on [Google Gemini CLI](https://github.com/google-gemini/gemini-cli) and [QwenLM qwen-code](https://github.com/QwenLM/qwen-code). We acknowledge and appreciate the excellent work of the Gemini CLI and Qwen team. 

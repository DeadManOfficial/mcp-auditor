# Contributing to MCP Auditor

First off, thank you for considering contributing to MCP Auditor! 🎉

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Coding Standards](#coding-standards)
- [Adding New Audit Tools](#adding-new-audit-tools)

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the maintainers.

## Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn
- Git
- TypeScript knowledge

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/mcp-auditor.git
cd mcp-auditor

# Install dependencies
npm install

# Build the project
npm run build

# Run in development mode (with hot reload)
npm run dev
```

### Testing Your Changes

```bash
# Run the self-audit to test
npx tsx self-audit.ts

# Test with Claude Desktop
# Add to your config:
{
  "mcpServers": {
    "mcp-auditor-dev": {
      "command": "node",
      "args": ["/path/to/mcp-auditor/dist/index.js"]
    }
  }
}
```

## Making Changes

### Branch Naming

- `feature/` - New features (e.g., `feature/add-sarbanes-oxley`)
- `fix/` - Bug fixes (e.g., `fix/benford-calculation`)
- `docs/` - Documentation (e.g., `docs/update-readme`)
- `refactor/` - Code refactoring (e.g., `refactor/handler-modules`)

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add SARBANES-OXLEY compliance framework
fix: correct chi-square calculation in Benford analysis
docs: update installation instructions for Windows
refactor: extract constants from engine module
```

## Submitting a Pull Request

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'feat: add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### PR Checklist

- [ ] Code compiles without errors (`npm run build`)
- [ ] Self-audit passes (`npx tsx self-audit.ts`)
- [ ] New tools are documented in README
- [ ] TypeScript types are complete
- [ ] No hardcoded magic numbers (use constants.ts)

## Coding Standards

### TypeScript Guidelines

```typescript
// ✅ Good: Use explicit types
export async function handleAuditCode(args: ToolArgs): Promise<ToolResult> {
  const code = args.code as string;
  // ...
}

// ❌ Bad: Implicit any
export async function handleAuditCode(args) {
  const code = args.code;
  // ...
}
```

### Constants

All magic numbers should be in `src/core/constants.ts`:

```typescript
// ✅ Good
import { SEVERITY_WEIGHTS } from '../core/constants.js';
const score = SEVERITY_WEIGHTS[finding.severity];

// ❌ Bad
const score = finding.severity === 'CRITICAL' ? 40 : 25;
```

### Handler Pattern

New tools should follow the handler pattern:

```typescript
// src/handlers/my-audit.ts
import { ToolResult, ToolArgs } from './types.js';

export async function handleMyTool(args: ToolArgs): Promise<ToolResult> {
  // Implementation
  return {
    content: [{
      type: 'text',
      text: JSON.stringify(result, null, 2)
    }]
  };
}
```

## Adding New Audit Tools

### 1. Define the Tool Schema

Add to `TOOLS` array in `src/index.ts`:

```typescript
{
  name: 'my_new_tool',
  description: 'Clear description of what this tool does',
  inputSchema: {
    type: 'object',
    properties: {
      param1: { type: 'string', description: 'Description' },
      param2: { type: 'number', description: 'Description' }
    },
    required: ['param1']
  }
}
```

### 2. Create the Handler

Create or update a handler file in `src/handlers/`:

```typescript
export async function handleMyNewTool(args: ToolArgs): Promise<ToolResult> {
  const param1 = args.param1 as string;

  // Your audit logic here

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({ /* results */ }, null, 2)
    }]
  };
}
```

### 3. Register the Handler

Add to `TOOL_HANDLERS` map in `src/index.ts`:

```typescript
const TOOL_HANDLERS = {
  // ... existing handlers
  'my_new_tool': handleMyNewTool,
};
```

### 4. Export from Index

Update `src/handlers/index.ts`:

```typescript
export { handleMyNewTool } from './my-audit.js';
```

### 5. Document

Add to README.md tools reference table.

## Questions?

Feel free to open an issue for:
- Bug reports
- Feature requests
- Questions about the codebase

Thank you for contributing! 🙌

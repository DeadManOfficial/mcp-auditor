/**
 * Handler Types
 */

export interface ToolResult {
  content: Array<{
    type: 'text';
    text: string;
  }>;
  isError?: boolean;
}

export type ToolArgs = Record<string, unknown>;

export type ToolHandler = (args: ToolArgs) => Promise<ToolResult>;

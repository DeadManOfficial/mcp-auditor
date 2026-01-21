/**
 * Audit Logger - Structured logging for MCP Auditor
 * Provides forensic-grade logging with timestamps and duration tracking
 */

interface AuditLogEntry {
  timestamp: string;
  tool: string;
  status: 'start' | 'complete' | 'error';
  duration?: number;
  error?: string;
}

const logs: AuditLogEntry[] = [];
const startTimes: Map<string, number> = new Map();

/**
 * Log tool invocation start
 */
export function logToolStart(tool: string): void {
  const timestamp = new Date().toISOString();
  const requestId = `${tool}-${Date.now()}`;
  startTimes.set(requestId, Date.now());

  logs.push({
    timestamp,
    tool,
    status: 'start'
  });

  // Log to stderr (won't interfere with MCP stdout)
  console.error(`[${timestamp}] AUDIT: ${tool} - START`);

  return;
}

/**
 * Log tool invocation completion
 */
export function logToolComplete(tool: string, startTime: number): void {
  const timestamp = new Date().toISOString();
  const duration = Date.now() - startTime;

  logs.push({
    timestamp,
    tool,
    status: 'complete',
    duration
  });

  console.error(`[${timestamp}] AUDIT: ${tool} - COMPLETE (${duration}ms)`);
}

/**
 * Log tool invocation error
 */
export function logToolError(tool: string, error: string, startTime?: number): void {
  const timestamp = new Date().toISOString();
  const duration = startTime ? Date.now() - startTime : undefined;

  logs.push({
    timestamp,
    tool,
    status: 'error',
    duration,
    error
  });

  console.error(`[${timestamp}] AUDIT: ${tool} - ERROR: ${error}${duration ? ` (${duration}ms)` : ''}`);
}

/**
 * Wrap a handler function with audit logging
 */
export async function withAuditLogging<T>(
  tool: string,
  handler: () => Promise<T>
): Promise<T> {
  const startTime = Date.now();
  logToolStart(tool);

  try {
    const result = await handler();
    logToolComplete(tool, startTime);
    return result;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    logToolError(tool, errorMsg, startTime);
    throw error;
  }
}

/**
 * Get all audit logs
 */
export function getAuditLogs(): AuditLogEntry[] {
  return [...logs];
}

/**
 * Clear audit logs
 */
export function clearAuditLogs(): void {
  logs.length = 0;
  startTimes.clear();
}

/**
 * Get audit summary statistics
 */
export function getAuditSummary(): {
  totalCalls: number;
  successfulCalls: number;
  failedCalls: number;
  averageDuration: number;
  toolUsage: Record<string, number>;
} {
  const completedLogs = logs.filter(l => l.status === 'complete');
  const errorLogs = logs.filter(l => l.status === 'error');

  const durations = completedLogs
    .map(l => l.duration)
    .filter((d): d is number => d !== undefined);

  const avgDuration = durations.length > 0
    ? durations.reduce((a, b) => a + b, 0) / durations.length
    : 0;

  const toolUsage: Record<string, number> = {};
  logs.filter(l => l.status === 'start').forEach(l => {
    toolUsage[l.tool] = (toolUsage[l.tool] || 0) + 1;
  });

  return {
    totalCalls: logs.filter(l => l.status === 'start').length,
    successfulCalls: completedLogs.length,
    failedCalls: errorLogs.length,
    averageDuration: Math.round(avgDuration),
    toolUsage
  };
}

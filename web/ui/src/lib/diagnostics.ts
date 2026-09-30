import type { ProbeTimings } from './network'
export interface DiagnosticRequest { type: string; target: string; source_ip?: string; resolver?: string }
export interface DiagnosticResult {
 type: string; started_at: number; duration_ms: number; outcome: string; addresses?: string[]; output?: string; truncated?: boolean
 measurement?: { latency_ms: number; mbps?: number; bytes?: number; http_status?: number; timings?: ProbeTimings }
}

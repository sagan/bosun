import type { ProbeTimings } from './network'
export interface DiagnosticRequest { type: string; target: string; source_ip?: string; resolver?: string; services?: boolean }
export interface DiagnosticResult {
 type: string; started_at: number; duration_ms: number; outcome: string; addresses?: string[]; output?: string; truncated?: boolean
 exit?: ExitReport
 measurement?: { latency_ms: number; mbps?: number; bytes?: number; http_status?: number; timings?: ProbeTimings }
}

export interface ExitReport {
 schema: number; tool?: string; timestamp?: string
 identity?: { ipv4?: string; ipv6?: string; asn?: number; as_name?: string; org?: string; as_country?: string }
 reputation?: { type?: string; risk?: number; country?: string; region?: string; city?: string; flags?: string[]; error?: string }
 geo?: Record<string, { id: string; name: string; ipv4?: { value?: string; country?: string; error?: string }; ipv6?: { value?: string; country?: string; error?: string } }[]>
 stash_checks?: ExitService[]; ai_endpoints?: ExitService[]
}
interface ExitService { id: string; name: string; state: string; region?: string; detail?: string; error?: string }

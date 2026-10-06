import type { Ingress } from './api'
export function ingressPort(g: Ingress, local: number): number {
  if (g.port_mappings?.length) {
    const m = g.port_mappings.find(m => local >= m.local_from && local <= m.local_to)
    return m ? m.public_from + local - m.local_from : 0
  }
  if (g.port_from && (local < g.port_from || local > g.port_to)) return 0
  const p = local + g.port_offset
  return p > 0 && p <= 65535 ? p : 0
}
export function firstFreeIngressPort(g: Ingress, used: number[] = []): number {
  const ranges = g.port_mappings?.length ? g.port_mappings.map(m => [m.local_from, m.local_to]) : [[g.port_from || 1024, g.port_to || 65535]]
  for (const [from, to] of ranges) for (let p = from; p <= to; p++) if (!used.includes(p) && !g.reserved_ports?.includes(p) && ingressPort(g, p)) return p
  return 0
}
export const ingressPortLabel = (g: Ingress): string => g.port_mappings?.length ? g.port_mappings.map(m => `${m.local_from}–${m.local_to} → ${m.public_from}–${m.public_from + m.local_to - m.local_from}`).join(', ') : g.port_from ? `${g.port_from}–${g.port_to}${g.port_offset ? ` (${g.port_offset > 0 ? '+' : ''}${g.port_offset})` : ''}` : ''
export const hostPort = (host: string, port: number) => `${host.includes(':') ? `[${host}]` : host}:${port}`

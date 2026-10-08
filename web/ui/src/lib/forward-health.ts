export interface ForwardHealthStatus { health?: string; probe_protocol?: string; up: boolean; rtt_ms: number; last_error?: string }

// Older UDP/mixed reports used TCP results without recording the transport.
export function forwardHealth(status: ForwardHealthStatus, protocol: string) {
  const transport = status.probe_protocol || (protocol === 'tcp' ? 'tcp' : 'none')
  const state = status.health || (protocol === 'tcp' ? (status.up ? 'up' : 'down') : 'unknown')
  return { state, transport, color: state === 'unknown' ? 'gray' : state === 'up' ? 'teal' : 'red', udpUnknown: protocol === 'both' && transport !== 'backend' }
}

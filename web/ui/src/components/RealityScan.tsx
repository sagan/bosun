import { Badge, Button, Group, Stack, Table, Text, Tooltip } from '@mantine/core'
import { IconCheck, IconX } from '@tabler/icons-react'
import { useLayoutEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from '../lib/notify'

// One probed REALITY target as the node reports it.
export interface RealityResult {
  host: string; port: number; ip?: string; feasible: boolean; reason?: string
  tls13: boolean; h2: boolean; x25519: boolean; cert_valid: boolean; cdn?: string
  cert_subject?: string; cert_issuer?: string; server_names?: string[]; latency_ms: number
  tls_record_bytes?: number; tls_record_limit?: number; tls_record_ok?: boolean | null; reason_code?: string
}

// RealityScan runs the node-side probe over the built-in pool ("auto":
// picks the fastest feasible target) or over the host currently typed in,
// and lets the operator pick a row. `scan` is the transport: a direct call
// on the standalone panel, a node job on Captain.
export function RealityScan({ current, scan, onPick }: { current: string; scan: (hosts: string[], signal?: AbortSignal) => Promise<RealityResult[]>; onPick: (host: string) => void }) {
  const { t } = useTranslation()
  const pending = useRef<AbortController | null>(null)
  const [request, setRequest] = useState<{ mode: 'auto' | 'one'; current: string; controller: AbortController } | null>(null)
  const [result, setResult] = useState<{ rows: RealityResult[]; current: string; picked?: string } | null>(null)
  // A result belongs to this mounted node and the input that started it.
  // Closing/reordering a wizard or typing another target cannot apply it.
  useLayoutEffect(() => () => { pending.current?.abort(); pending.current = null }, [current])
  const busy = request && request.current === current && !request.controller.signal.aborted ? request.mode : null
  const rows = result && (result.current === current || result.picked === current) ? result.rows : null
  const selectable = (r: RealityResult) => r.feasible && r.tls_record_ok !== false
  const pick = (host: string) => { setResult(r => r ? { ...r, picked: host } : r); onPick(host) }
  const run = async (mode: 'auto' | 'one') => {
    pending.current?.abort()
    const controller = new AbortController()
    pending.current = controller
    setRequest({ mode, current, controller })
    try {
      const out = await scan(mode === 'one' ? [current.trim()] : [], controller.signal)
      if (pending.current !== controller || controller.signal.aborted) return
      const best = mode === 'auto' ? out.find(selectable) : undefined
      setResult({ rows: out, current, picked: best?.host })
      if (mode === 'auto') {
        if (best) { onPick(best.host); toast.ok(t('inbounds.realityPicked', { host: best.host, ms: best.latency_ms })) } else toast.err(new Error(t('inbounds.realityNone')))
      }
    } catch (e) {
      if (pending.current === controller && !controller.signal.aborted) toast.err(e)
    } finally {
      if (pending.current === controller) { pending.current = null; setRequest(null) }
    }
  }
  const mark = (v: boolean) => (v ? <IconCheck size={14} color="var(--mantine-color-teal-6)" /> : <IconX size={14} color="var(--mantine-color-red-6)" />)
  return (
    <Stack gap="xs">
      <Group gap="xs">
        <Button size="xs" variant="light" loading={busy === 'auto'} disabled={busy !== null} onClick={() => run('auto')}>{t('inbounds.realityAuto')}</Button>
        <Button size="xs" variant="default" loading={busy === 'one'} disabled={busy !== null || !current.trim()} onClick={() => run('one')}>{t('inbounds.realityProbe')}</Button>
        {busy && <Text size="xs" c="dimmed">{t('inbounds.realityScanning')}</Text>}
      </Group>
      <Text size="xs" c="dimmed">{t('inbounds.realityScanHint')}</Text>
      {rows && (
        <Table.ScrollContainer minWidth={640}>
          <Table verticalSpacing={4} fz="xs">
            <Table.Thead style={{ whiteSpace: 'nowrap' }}><Table.Tr>
              <Table.Th>{t('inbounds.handshakeServer')}</Table.Th><Table.Th>{t('inbounds.realityLatency')}</Table.Th>
              <Table.Th>TLS 1.3</Table.Th><Table.Th>h2</Table.Th><Table.Th>X25519</Table.Th><Table.Th>{t('inbounds.realityCert')}</Table.Th>
              <Table.Th>{t('inbounds.realityRecord')}</Table.Th>
              <Table.Th>CDN</Table.Th><Table.Th /></Table.Tr></Table.Thead>
            <Table.Tbody>
              {rows.map((r) => (
                <Table.Tr key={r.host + r.port}>
                  <Table.Td>
                    <Text size="xs" fw={600}>{r.host}{r.port !== 443 ? `:${r.port}` : ''}</Text>
                    {r.reason && <Text size="xs" c={r.feasible ? 'dimmed' : 'red'}>{r.reason_code === 'tls_record_too_large' ? t('inbounds.realityRecordTooLarge', { bytes: r.tls_record_bytes, limit: r.tls_record_limit }) : r.reason}</Text>}
                    {r.feasible && r.cert_issuer && <Text size="xs" c="dimmed">{r.cert_issuer}</Text>}
                  </Table.Td>
                  <Table.Td>{r.latency_ms >= 0 ? `${r.latency_ms} ms` : '—'}</Table.Td>
                  <Table.Td>{mark(r.tls13)}</Table.Td><Table.Td>{mark(r.h2)}</Table.Td><Table.Td>{mark(r.x25519)}</Table.Td><Table.Td>{mark(r.cert_valid)}</Table.Td>
                  <Table.Td>{typeof r.tls_record_ok === 'boolean' ? <Tooltip label={t('inbounds.realityRecordHint', { limit: r.tls_record_limit })}><Badge miw="max-content" color={r.tls_record_ok ? 'teal' : 'red'} size="xs">{r.tls_record_bytes} B</Badge></Tooltip> : <Tooltip label={t('inbounds.realityRecordUnknownHint')}><Badge miw="max-content" color="yellow" size="xs">{t('inbounds.realityRecordUnknown')}</Badge></Tooltip>}</Table.Td>
                  <Table.Td>{r.cdn ? <Tooltip label={t('inbounds.realityCdnHint')}><Badge color="red" size="xs">{r.cdn}</Badge></Tooltip> : <Text size="xs" c="dimmed">{t('inbounds.realityNoCdn')}</Text>}</Table.Td>
                  <Table.Td>{selectable(r) ? <Button size="compact-xs" variant="light" onClick={() => pick(r.host)}>{t('inbounds.realityUse')}</Button> : <Text size="xs" c="dimmed">{t('inbounds.realityBlocked')}</Text>}</Table.Td>
                </Table.Tr>
              ))}
              {rows.length === 0 && <Table.Tr><Table.Td colSpan={9}><Text size="xs" c="dimmed">{t('inbounds.realityNone')}</Text></Table.Td></Table.Tr>}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Stack>
  )
}

import { Alert, Badge, Button, Code, Group, Select, SimpleGrid, Stack, Text, TextInput } from '@mantine/core'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { DiagnosticRequest, DiagnosticResult } from '../lib/diagnostics'

export function DiagnosticForm({ onRun, pending }: { onRun: (v: DiagnosticRequest) => void; pending: boolean }) {
 const { t } = useTranslation()
 const [type, setType] = useState('dns')
 const [target, setTarget] = useState('')
 const [source, setSource] = useState('')
 const [resolver, setResolver] = useState('')
 const placeholder = type === 'http' || type === 'download' ? 'https://example.com/' : type === 'tcp' ? 'example.com:443' : 'example.com'
 return <form onSubmit={(e) => { e.preventDefault(); if (!pending && target.trim()) onRun({ type, target: target.trim(), source_ip: source.trim(), resolver: type === 'dns' ? resolver.trim() : '' }) }}><Stack gap="sm">
  <Text size="sm" c="dimmed">{t('diagnostics.hint')}</Text>
  <SimpleGrid cols={{ base: 1, sm: 2 }}>
   <Select label={t('diagnostics.type')} value={type} onChange={(v) => { if (v) { setType(v); setTarget('') } }} allowDeselect={false} disabled={pending} data={['dns', 'tcp', 'http', 'download', 'mtr', 'traceroute'].map((value) => ({ value, label: t(`diagnostics.types.${value}`) }))} />
   <TextInput label={t('diagnostics.target')} value={target} onChange={(e) => setTarget(e.currentTarget.value)} placeholder={placeholder} maxLength={2048} required disabled={pending} />
   <TextInput label={t('diagnostics.source')} value={source} onChange={(e) => setSource(e.currentTarget.value)} placeholder="10.10.0.2" disabled={pending} />
   {type === 'dns' && <TextInput label={t('diagnostics.resolver')} value={resolver} onChange={(e) => setResolver(e.currentTarget.value)} placeholder={t('diagnostics.systemResolver')} disabled={pending} />}
  </SimpleGrid>
  <Text size="xs" c="dimmed">{type === 'download' ? t('diagnostics.downloadHint') : type === 'mtr' || type === 'traceroute' ? t('diagnostics.routeHint') : t('diagnostics.serviceHint')}</Text>
  <Group><Button type="submit" loading={pending} disabled={!target.trim()}>{t('diagnostics.run')}</Button>{pending && <Text size="sm" c="dimmed">{t('diagnostics.pending')}</Text>}</Group>
 </Stack></form>
}
const ms = (v: number | null | undefined) => v == null || v < 0 ? '—' : `${v.toFixed(1)} ms`
export function DiagnosticResultView({ result }: { result: DiagnosticResult }) {
 const { t } = useTranslation()
 const m = result.measurement
 const special = ['busy', 'unavailable', 'failed'].includes(result.outcome)
 return <Stack gap="xs" mt="sm">
  <Group><Badge color={result.outcome === 'ok' ? 'teal' : 'orange'}>{result.outcome === 'ok' && ['mtr', 'traceroute'].includes(result.type) ? t('diagnostics.completed') : special ? t(`diagnostics.outcomes.${result.outcome}`) : t(`networkQuality.outcomes.${result.outcome}`)}</Badge><Text size="xs" c="dimmed">{new Date(result.started_at * 1000).toLocaleString()} · {t('networkQuality.duration')}: {ms(result.duration_ms)}</Text></Group>
  {result.outcome === 'unavailable' && <Alert color="orange">{t('diagnostics.installHint')}</Alert>}
  {result.addresses?.length ? <Text size="sm" style={{ overflowWrap: 'anywhere' }}>{result.addresses.join(' · ')}</Text> : null}
  {m && <Group gap="md"><Text size="sm">{t('networkQuality.latency')}: {ms(m.latency_ms)}</Text>{m.http_status ? <Text size="sm">HTTP {m.http_status}</Text> : null}{m.mbps != null && <Text size="sm">{m.mbps.toFixed(2)} Mbps</Text>}{m.bytes != null && <Text size="sm">{(m.bytes / 2 ** 20).toFixed(2)} MiB</Text>}</Group>}
  {m?.timings && <Group gap="md">{(['dns_ms', 'connect_ms', 'tls_ms', 'response_ms'] as const).map((phase) => <Text key={phase} size="xs" c="dimmed">{t(`networkQuality.phases.${phase}`)}: {ms(m.timings?.[phase])}</Text>)}</Group>}
  {result.output && <Code block style={{ maxHeight: 420, overflow: 'auto', whiteSpace: 'pre' }}>{result.output}</Code>}
  {result.truncated && <Text size="xs" c="orange">{t('diagnostics.truncated')}</Text>}
 </Stack>
}

import { Badge, Button, Group, SimpleGrid, Stack, Table, Text } from '@mantine/core'
import { useTranslation } from 'react-i18next'
import type { ExitReport } from '../lib/diagnostics'

export function ExitDiagnosticView({ report }: { report: ExitReport }) {
 const { t } = useTranslation()
 const identity = report.identity ?? {}
 const checks = Object.values(report.geo ?? {}).flatMap(rows => Array.isArray(rows) ? rows : [])
 const services = [...(report.stash_checks ?? []), ...(report.ai_endpoints ?? [])]
 const value = (v?: { value?: string; country?: string; error?: string } | null) => v?.error || [v?.value, v?.country].filter(Boolean).join(' · ') || '—'
 const download = () => {
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }))
  const a = document.createElement('a'); a.href = url; a.download = 'exit-diagnostic.json'; a.click(); URL.revokeObjectURL(url)
 }
 return <Stack gap="sm">
  <Group justify="space-between"><Text fw={600}>{t('exitDiagnostic.report')}</Text><Button size="xs" variant="default" onClick={download}>{t('exitDiagnostic.export')}</Button></Group>
  <SimpleGrid cols={{ base: 1, sm: 2 }}>
   {[['IPv4', identity.ipv4], ['IPv6', identity.ipv6], ['ASN', identity.asn ? `AS${identity.asn} ${identity.as_name || identity.org || ''}` : ''], [t('exitDiagnostic.country'), identity.as_country]].map(([label, val]) => <div key={label}><Text size="xs" c="dimmed">{label}</Text><Text size="sm" style={{ overflowWrap: 'anywhere' }}>{val || '—'}</Text></div>)}
  </SimpleGrid>
  {report.reputation && <div><Text size="sm" fw={500}>{t('exitDiagnostic.reputation')}</Text><Text size="sm">{report.reputation.error || [report.reputation.type, report.reputation.country, report.reputation.region, report.reputation.city].filter(Boolean).join(' · ') || '—'}</Text>{!report.reputation.error && <Text size="xs" c="dimmed">{t('exitDiagnostic.risk', { score: report.reputation.risk ?? '—' })} · {(report.reputation.flags ?? []).join(', ')}</Text>}</div>}
  <Text size="xs" c="dimmed">{t('exitDiagnostic.evidence')}</Text>
  {checks.length > 0 && <Table.ScrollContainer minWidth={460}><Table><Table.Thead><Table.Tr><Table.Th>{t('exitDiagnostic.provider')}</Table.Th><Table.Th>IPv4</Table.Th><Table.Th>IPv6</Table.Th></Table.Tr></Table.Thead><Table.Tbody>{checks.map((c, i) => <Table.Tr key={`${c.id}-${i}`}><Table.Td>{c.name}</Table.Td><Table.Td><Text size="xs" c={c.ipv4?.error ? 'dimmed' : undefined}>{value(c.ipv4)}</Text></Table.Td><Table.Td><Text size="xs" c={c.ipv6?.error ? 'dimmed' : undefined}>{value(c.ipv6)}</Text></Table.Td></Table.Tr>)}</Table.Tbody></Table></Table.ScrollContainer>}
  {services.length > 0 && <Table.ScrollContainer minWidth={460}><Table><Table.Thead><Table.Tr><Table.Th>{t('exitDiagnostic.service')}</Table.Th><Table.Th>{t('exitDiagnostic.verdict')}</Table.Th><Table.Th>{t('exitDiagnostic.details')}</Table.Th></Table.Tr></Table.Thead><Table.Tbody>{services.map((s, i) => <Table.Tr key={`${s.id}-${i}`}><Table.Td>{s.name}</Table.Td><Table.Td><Badge variant="light" color="gray">{s.state || 'unknown'}</Badge></Table.Td><Table.Td><Text size="xs" style={{ overflowWrap: 'anywhere' }}>{[s.region, s.error || s.detail].filter(Boolean).join(' · ') || '—'}</Text></Table.Td></Table.Tr>)}</Table.Tbody></Table></Table.ScrollContainer>}
 </Stack>
}

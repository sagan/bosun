import { Badge, Group, Stack, Table, Text } from '@mantine/core'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { GPUStatus } from '../lib/resources'
import { bytes } from '../lib/format'

// GPU samples have an independent clock. A new host beat cannot freshen them.
export function GPUResources({ value }: { value?: GPUStatus }) {
 const { t } = useTranslation()
 const [now, setNow] = useState(Date.now)
 useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 10_000); return () => window.clearInterval(timer) }, [])
 const stale = !!value?.at && now - value.at > 60_000
 const state = value?.state ?? 'legacy'
 const known = ['legacy', 'disabled', 'pending', 'ok', 'partial', 'unavailable', 'error', 'unsupported'].includes(state) ? state : 'error'
 return <Stack gap="sm">
  <Group><Badge color={stale || !['ok', 'disabled'].includes(known) ? 'orange' : 'gray'}>{stale ? t('resources.stale') : t(`gpu.states.${known}`)}</Badge>{value?.at ? <Text size="xs" c="dimmed">{t('resources.sampled')}: {new Date(value.at).toLocaleString()}</Text> : null}</Group>
  <Text size="xs" c="dimmed">{t('gpu.hint')}</Text>
  {!!value?.devices?.length && <Table.ScrollContainer minWidth={720}><Table striped fz="sm">
   <Table.Thead><Table.Tr>{['device', 'utilization', 'memory', 'temperature', 'power'].map((k) => <Table.Th key={k}>{t(`gpu.${k}`)}</Table.Th>)}</Table.Tr></Table.Thead>
   <Table.Tbody>{value.devices.map((d) => <Table.Tr key={d.id}>
    <Table.Td><Text size="sm">{d.name}</Text><Text size="xs" c="dimmed">{d.id}</Text></Table.Td>
    <Table.Td>{d.utilization == null ? '—' : `${d.utilization.toFixed(1)}%`}</Table.Td>
    <Table.Td>{d.memory_used == null || d.memory_total == null ? '—' : `${bytes(d.memory_used)} / ${bytes(d.memory_total)}`}</Table.Td>
    <Table.Td>{d.temperature == null ? '—' : `${d.temperature.toFixed(1)} °C`}</Table.Td>
    <Table.Td>{d.power == null ? '—' : `${d.power.toFixed(1)} W`}</Table.Td>
   </Table.Tr>)}</Table.Tbody>
  </Table></Table.ScrollContainer>}
  {value?.truncated && <Text size="xs" c="orange">{t('gpu.truncated')}</Text>}
 </Stack>
}

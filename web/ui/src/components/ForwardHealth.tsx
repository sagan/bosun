import { Badge, Group, Tooltip } from '@mantine/core'
import { useTranslation } from 'react-i18next'
import { forwardHealth, type ForwardHealthStatus } from '../lib/forward-health'

export function ForwardHealth({ status, protocol }: { status: ForwardHealthStatus; protocol: string }) {
  const { t } = useTranslation()
  const h = forwardHealth(status, protocol)
  const label = h.transport === 'backend' ? t('forwards.backendFailed') : h.state === 'unknown' ? t('forwards.unknown') : h.state === 'up' ? `${status.rtt_ms} ms` : t('forwards.down')
  return <Group gap={4} wrap="wrap">
    <Tooltip label={status.last_error || (h.transport === 'tcp' ? t('forwards.tcpProbe') : t('forwards.udpUntested'))}>
      <Badge size="xs" color={h.color} variant="light">{h.transport === 'tcp' ? 'TCP · ' : ''}{label}</Badge>
    </Tooltip>
    {h.udpUnknown && <Tooltip label={t('forwards.udpUntested')}><Badge size="xs" color="gray" variant="light">UDP · {t('forwards.unknown')}</Badge></Tooltip>}
  </Group>
}

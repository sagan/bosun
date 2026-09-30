import { SimpleGrid, Switch, TagsInput, Text } from '@mantine/core'
import { useTranslation } from 'react-i18next'
import type { ResourceOptions } from '../lib/resources'

export function ResourceOptionsFields({ value, onChange, disabled }: { value?: ResourceOptions; onChange: (v: ResourceOptions) => void; disabled?: boolean }) {
  const { t } = useTranslation()
  return <div><SimpleGrid cols={{ base: 1, sm: 2 }}>
    <TagsInput label={t('resources.includeInterfaces')} placeholder="eth0, eth1" value={value?.include_interfaces ?? []} onChange={(v) => onChange({ ...value, include_interfaces: v })} disabled={disabled} />
    <TagsInput label={t('resources.excludeInterfaces')} placeholder="docker0, tun0" value={value?.exclude_interfaces ?? []} onChange={(v) => onChange({ ...value, exclude_interfaces: v })} disabled={disabled} />
  </SimpleGrid><Text size="xs" c="dimmed" mt={4}>{t('resources.selectionHint')}</Text><Switch mt="md" label={t('gpu.enabled')} checked={value?.gpu ?? false} onChange={(e) => onChange({ ...value, gpu: e.currentTarget.checked })} disabled={disabled} /><Text size="xs" c="dimmed" mt={4}>{t('gpu.enableHint')}</Text></div>
}

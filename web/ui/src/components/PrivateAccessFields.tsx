import { Button, Card, Checkbox, Group, NumberInput, Select, SimpleGrid, Stack, Text, TextInput } from '@mantine/core'
import { useTranslation } from 'react-i18next'

type Rule = { cidr: string; protocol?: string; port_start?: number; port_end?: number }
type Policy = { mode: string; enforcement?: string; allow_core_only?: boolean; rules?: Rule[] }
const policyOf = (json: string): Policy => { try { return JSON.parse(json || '{}').private_access || { mode: 'off' } } catch { return { mode: 'off' } } }

export function PrivateAccessFields({ json, onChange, disabled = false, runtimeMode }: { json: string; onChange: (json: string) => void; disabled?: boolean; runtimeMode?: string }) {
  const { t } = useTranslation()
  const value = policyOf(json)
  const update = (policy: Policy) => {
    let settings: Record<string, unknown>
    try { settings = JSON.parse(json || '{}') } catch { return }
    onChange(JSON.stringify({ ...settings, private_access: policy.mode === 'off' ? policy : { ...policy, enforcement: runtimeMode ? 'auto' : (policy.enforcement || value.enforcement || 'dual'), allow_core_only: policy.allow_core_only ?? value.allow_core_only ?? false } }, null, 2))
  }
  const rules = Array.isArray(value.rules) ? value.rules.filter((r) => r && typeof r === 'object') : []
  const edit = (i: number, patch: Partial<Rule>) => update({ mode: 'custom', rules: rules.map((r, j) => j === i ? { ...r, ...patch } : r) })
  return <Card withBorder padding="sm"><Stack gap="sm">
    <Select label={t('privateAccess.title')} description={t('privateAccess.hint')} inputWrapperOrder={['label', 'input', 'description', 'error']} value={value.mode} disabled={disabled} allowDeselect={false}
      data={[{ value: 'off', label: t('privateAccess.off') }, { value: 'internal', label: t('privateAccess.internal') }, { value: 'custom', label: t('privateAccess.custom') }]}
      onChange={(mode) => update(mode === 'custom' ? { mode, rules: rules.length ? rules : [{ cidr: '', protocol: '', port_start: 0, port_end: 0 }] } : { mode: mode || 'off' })} />
    {value.mode !== 'off' && <Text size="sm">{t('privateAccess.actualMode')}: {t(runtimeMode === 'core_only' ? 'privateAccess.coreOnly' : runtimeMode === 'dual' ? 'privateAccess.dual' : 'privateAccess.runtimeUnknown')}</Text>}
    {value.mode !== 'off' && runtimeMode === 'core_only' && <><Text size="sm" c="orange">{t('privateAccess.coreOnlyHint')}</Text><Checkbox label={t('privateAccess.confirmCoreOnly')} checked={!!value.allow_core_only} disabled={disabled} onChange={event => update({...value, enforcement:'auto', allow_core_only:event.currentTarget.checked})} /></>}
    {value.mode !== 'off' && runtimeMode !== 'core_only' && <Text size="xs" c="dimmed">{t('privateAccess.protection')}</Text>}
    {value.mode === 'custom' && <>
      {rules.map((rule, i) => <Card withBorder padding="xs" key={i}><Stack gap="xs">
        <SimpleGrid cols={{ base: 1, sm: 2 }}><TextInput label={t('privateAccess.address')} placeholder="10.10.0.2/32" value={typeof rule.cidr === 'string' ? rule.cidr : ''} disabled={disabled} onChange={(e) => edit(i, { cidr: e.currentTarget.value })} />
          <Select label={t('privateAccess.protocol')} value={rule.protocol || ''} disabled={disabled} allowDeselect={false} data={[{ value: '', label: 'TCP + UDP' }, 'tcp', 'udp']} onChange={(protocol) => edit(i, { protocol: protocol || '' })} /></SimpleGrid>
        <SimpleGrid cols={{ base: 1, sm: 2 }}><NumberInput label={t('privateAccess.portStart')} value={rule.port_start || 0} min={0} max={65535} disabled={disabled} onChange={(n) => edit(i, { port_start: Number(n) })} />
          <NumberInput label={t('privateAccess.portEnd')} value={rule.port_end || 0} min={0} max={65535} disabled={disabled} onChange={(n) => edit(i, { port_end: Number(n) })} /></SimpleGrid>
        <Text size="xs" c="dimmed">{t('privateAccess.portsHint')}</Text>
        <Group justify="flex-end"><Button variant="subtle" color="red" size="xs" disabled={disabled} onClick={() => update({ mode: 'custom', rules: rules.filter((_, j) => j !== i) })}>{t('privateAccess.remove')}</Button></Group>
      </Stack></Card>)}
      <Button variant="light" size="xs" disabled={disabled || rules.length >= 64} onClick={() => update({ mode: 'custom', rules: [...rules, { cidr: '' }] })}>{t('privateAccess.add')}</Button>
    </>}
  </Stack></Card>
}

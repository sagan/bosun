import { SettingsFields } from '../SettingsFields'
import { SettingsLoadState } from '../SettingsLoadState'
import { NumberInput, Textarea, TagsInput, Alert, Badge, Button, Card, Group, PasswordInput, Select, Stack, Switch, Table, Text, TextInput, Title } from '@mantine/core'
import { modals } from '@mantine/modals'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, type CoreRelease, type Settings, type Status } from '../../lib/api'
import { useSettingsForm as useForm } from '../../lib/settings-draft'
import { useAuth } from '../../lib/auth'
import { when } from '../../lib/format'
import { dnsToast, toast, type DNSResult } from '../../lib/notify'

export type NodeSettingsSection = 'node' | 'network' | 'runtime' | 'subscription' | 'notifications'
const fields: Record<NodeSettingsSection, (keyof Settings)[]> = {
  node: ['public_host', 'node_name'],
  network: ['acme_email', 'cloudflare_token', 'panel_domain', 'panel_acme', 'decoy_enabled', 'decoy_domain', 'decoy_upstream', 'decoy_acme', 'decoy_allow_private', 'decoy_insecure', 'panel_allow_cidrs'],
  runtime: ['user_speed_limit_mbps', 'mita_quotas'],
  subscription: ['extra_links'],
  notifications: ['telegram_token', 'telegram_chat_id', 'telegram_notify'],
}

export function NodeSettingsCard({ section }: { section: NodeSettingsSection }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const settings = useQuery({ queryKey: ['settings'], queryFn: () => api.get<Settings>('/api/settings') })
  const status = useQuery({ queryKey: ['status'], queryFn: () => api.get<Status>('/api/status'), enabled: section === 'network' || section === 'runtime', refetchInterval: section === 'network' || section === 'runtime' ? 5_000 : false })
  const sform = useForm<Settings>({ initialValues: { public_host: '', node_name: '', acme_email: '', cloudflare_token: '', panel_domain: '', panel_acme: 'http', decoy_enabled: false, decoy_domain: '', decoy_upstream: '', decoy_acme: 'http', decoy_allow_private: false, decoy_insecure: false, user_speed_limit_mbps: 0, mita_quotas: false, panel_allow_cidrs: [], extra_links: '', telegram_token: '', telegram_chat_id: 0, telegram_notify: true } })
  useEffect(() => { if (settings.data) sform.hydrate(settings.data) }, [settings.data]) // eslint-disable-line react-hooks/exhaustive-deps
  const saveSettings = useMutation({
    mutationFn: async (values: Settings) => {
      // PUT replaces the whole document. Refresh it and overlay only fields the
      // operator changed in this section, preserving other pages and secrets.
      const patch = Object.fromEntries(fields[section].filter(key => sform.isDirty(key)).map(key => [key, values[key]]))
      const latest = await api.get<Settings>('/api/settings')
      return api.put<{ ok: boolean; dns?: DNSResult[] }>('/api/settings', { ...latest, ...patch })
    },
    onSuccess: (r) => { toast.ok(t('common.saved')); dnsToast(r.dns); sform.resetDirty(); sform.hydrate({ ...sform.values, cloudflare_token: '', telegram_token: '' }); qc.invalidateQueries({ queryKey: ['settings'] }); qc.invalidateQueries({ queryKey: ['links'] }) }, onError: toast.err,
  })
  const s = status.data
  if (settings.data === undefined) return <SettingsLoadState query={settings} />
  return <Card><form onSubmit={sform.onSubmit(v => saveSettings.mutate(v))}>
    <fieldset disabled={!settings.data || saveSettings.isPending} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}><Stack gap="sm">
      {section === 'node' && <>
            <TextInput label={t('settings.publicHost')} description={t('settings.publicHostHint')} placeholder="node.example.com" {...sform.getInputProps('public_host')} />
            <TextInput label={t('settings.nodeName')} description={t('settings.nodeNameHint')} placeholder="JP-1" {...sform.getInputProps('node_name')} />
      </>}
      {section === 'network' && <>
            <Title order={6} mt="xs">{t('settings.certs')}</Title>
            <Text size="xs" c="dimmed">{t('settings.certsHint')}</Text>
            <TextInput label={t('settings.acmeEmail')} placeholder="you@example.com" {...sform.getInputProps('acme_email')} />
            <PasswordInput label={t('settings.cfToken')} description={settings.data?.has_cloudflare_token ? t('settings.tokenKeptHint') : t('settings.cfTokenHint')} placeholder={settings.data?.has_cloudflare_token ? '••••••••' : ''} {...sform.getInputProps('cloudflare_token')} />
            <SettingsFields>
              <TextInput label={t('settings.panelDomain')} description={t('settings.panelDomainHint')} placeholder="node.example.com" {...sform.getInputProps('panel_domain')} />
              <Select label={t('inbounds.acme')} data={[{ value: 'http', label: t('inbounds.acmeHttp') }, { value: 'dns', label: t('inbounds.acmeDns') }]} allowDeselect={false} {...sform.getInputProps('panel_acme')} />
            </SettingsFields>
            <Title order={6} mt="xs">{t('settings.decoy')}</Title>
            <Text size="xs" c="dimmed">{t('settings.decoyHint')}</Text>
            <Switch label={t('settings.decoyEnabled')} {...sform.getInputProps('decoy_enabled', { type: 'checkbox' })} />
            {sform.values.decoy_enabled && (
              <>
                <SettingsFields>
                  <TextInput label={t('settings.decoyDomain')} description={t('settings.decoyDomainHint')} placeholder="www.example.com" required {...sform.getInputProps('decoy_domain')} />
                  <Select label={t('inbounds.acme')} data={[{ value: 'http', label: t('inbounds.acmeHttp') }, { value: 'dns', label: t('inbounds.acmeDns') }]} allowDeselect={false} {...sform.getInputProps('decoy_acme')} />
                </SettingsFields>
                <TextInput label={t('settings.decoyUpstream')} description={t('settings.decoyUpstreamHint')} placeholder="https://www.example.com" {...sform.getInputProps('decoy_upstream')} />
                {sform.values.decoy_upstream && <SettingsFields>
                  <Switch label={t('settings.decoyAllowPrivate')} description={t('settings.decoyAllowPrivateHint')} {...sform.getInputProps('decoy_allow_private', { type: 'checkbox' })} />
                  <Switch label={t('settings.decoyInsecure')} description={t('settings.decoyInsecureHint')} {...sform.getInputProps('decoy_insecure', { type: 'checkbox' })} />
                </SettingsFields>}
                {s?.agent?.decoy && <Text size="xs" c={s.agent.decoy.error ? 'red' : s.agent.decoy.cert_ready ? 'teal' : 'orange'}>{s.agent.decoy.error ? s.agent.decoy.error : s.agent.decoy.cert_ready ? t('settings.decoyReady', { port: s.agent.decoy.port }) : t('settings.decoyPending')}</Text>}
              </>
            )}
            <Title order={6} mt="xs">{t('settings.access')}</Title>
            <TagsInput label={t('settings.allowCidrs')} description={t('settings.allowCidrsHint')} placeholder="203.0.113.0/24" value={sform.values.panel_allow_cidrs ?? []} onChange={(v) => sform.setFieldValue('panel_allow_cidrs', v)} />
      </>}
      {section === 'runtime' && <>
            <NumberInput label={t('settings.speedLimit')} description={t('settings.speedLimitHint')} min={0} {...sform.getInputProps('user_speed_limit_mbps')} />
            <Switch label={t('settings.mitaQuotas')} description={t('settings.mitaQuotasHint')} {...sform.getInputProps('mita_quotas', { type: 'checkbox' })} />
            {s?.agent?.shaper && <Text size="xs" c={s.agent.shaper.error ? 'red' : s.agent.shaper.supported ? 'teal' : 'orange'}>{s.agent.shaper.error ? s.agent.shaper.error : s.agent.shaper.supported ? t('settings.shaperOn', { n: s.agent.shaper.users, iface: s.agent.shaper.interface }) : t('settings.shaperUnsupported')}</Text>}
      </>}
      {section === 'subscription' && <>
            <Textarea label={t('settings.extraLinks')} description={t('settings.extraLinksHint')} autosize minRows={2} placeholder="vless://… (one per line)" {...sform.getInputProps('extra_links')} />
      </>}
      {section === 'notifications' && <>
            <Title order={6} mt="xs">{t('settings.telegram')}</Title>
            <Text size="xs" c="dimmed">{t('settings.telegramHint')}</Text>
            <SettingsFields>
              <PasswordInput label={t('settings.telegramToken')} description={settings.data?.has_telegram_token ? t('settings.tokenKeptHint') : undefined} placeholder={settings.data?.has_telegram_token ? '••••••••' : '123456:ABC…'} {...sform.getInputProps('telegram_token')} />
              <NumberInput label={t('settings.telegramChat')} description={t('settings.telegramChatHint')} hideControls value={sform.values.telegram_chat_id || ''} onChange={(v) => sform.setFieldValue('telegram_chat_id', Number(v) || 0)} />
            </SettingsFields>
            <Switch label={t('settings.telegramNotify')} {...sform.getInputProps('telegram_notify', { type: 'checkbox' })} />
      </>}
      <Group justify="flex-end"><Button type="submit" loading={saveSettings.isPending} disabled={!sform.isDirty()}>{t('common.save')}</Button></Group>
    </Stack></fieldset>
  </form></Card>
}

export function AdminAccountCard() {
  const { t } = useTranslation()
  const { me, refresh } = useAuth()
  const aform = useForm({ initialValues: { Username: me?.username ?? 'admin', Password: '', Confirm: '' }, validate: { Confirm: (v, all) => (v === all.Password ? null : t('settings.mismatch')) } })
  const saveAdmin = useMutation({ mutationFn: (v: { Username: string; Password: string }) => api.put('/api/admin', v), onSuccess: () => { toast.ok(t('common.saved')); aform.resetDirty(); aform.hydrate({ ...aform.values, Password: '', Confirm: '' }); refresh() }, onError: toast.err })
  return (
        <Card>
          <Title order={5} mb="xs">{t('settings.login')}</Title>
          <form onSubmit={aform.onSubmit((v) => saveAdmin.mutate({ Username: v.Username, Password: v.Password }))}><Stack gap="sm">
            <TextInput label={t('login.username')} required {...aform.getInputProps('Username')} />
            <SettingsFields>
              <PasswordInput label={t('settings.newPassword')} description={t('settings.newPasswordHint')} {...aform.getInputProps('Password')} />
              <PasswordInput label={t('settings.confirm')} {...aform.getInputProps('Confirm')} />
            </SettingsFields>
            <Group justify="flex-end"><Button type="submit" size="xs" loading={saveAdmin.isPending}>{t('common.save')}</Button></Group>
          </Stack></form>
        </Card>
  )
}

export function ModeCard() {
  const { t } = useTranslation()
  const { me, refresh } = useAuth()
  const qc = useQueryClient()
  const status = useQuery({ queryKey: ['status'], queryFn: () => api.get<Status>('/api/status'), refetchInterval: 5_000 })
  const s = status.data
  const fixed = !!me?.fixed
  const mform = useForm({ initialValues: { url: '', pair_code: '' } })
  const adopt = useMutation({ mutationFn: (v: { url: string; pair_code: string }) => api.post('/api/mode/adopt', v), onSuccess: () => { mform.resetDirty(); toast.ok(t('mode.adopted')); refresh(); qc.invalidateQueries() }, onError: toast.err })
  const [keep, setKeep] = useState(false)
  const detach = useMutation({ mutationFn: () => api.post('/api/mode/detach', { keep }), onSuccess: () => { toast.ok(t('mode.detached')); refresh(); qc.invalidateQueries() }, onError: toast.err })
  return (
      <Card mb="lg">
        <Group justify="space-between" mb="xs">
          <Title order={5}>{t('mode.title')}</Title>
          {s && <Badge color={fixed ? 'grape' : s.mode === 'managed' ? 'orange' : 'teal'}>{fixed ? t('mode.fixed', { driver: me?.fixed }) : t(`mode.${s.mode}`)}</Badge>}
        </Group>
        {fixed && <Text size="sm" c="dimmed">{t('mode.fixedHint', { driver: me?.fixed })}</Text>}
        {!fixed && s?.mode === 'local' && (
          <Stack gap="sm">
            <Text size="sm" c="dimmed">{t('mode.adoptHint')}</Text>
            <form onSubmit={mform.onSubmit((v) => { modals.openConfirmModal({ title: t('mode.adopt'), children: <Text size="sm">{t('mode.adoptConfirm')}</Text>, labels: { confirm: t('mode.adopt'), cancel: t('common.cancel') }, confirmProps: { color: 'orange' }, onConfirm: () => adopt.mutate(v) }) })}>
              <Group align="flex-end">
                <TextInput flex={2} label={t('mode.captainUrl')} placeholder="https://panel.example.com" required {...mform.getInputProps('url')} />
                <TextInput flex={1} label={t('mode.pairCode')} placeholder="ABCD-EFGH" required {...mform.getInputProps('pair_code')} />
                <Button type="submit" color="orange" loading={adopt.isPending}>{t('mode.adopt')}</Button>
              </Group>
            </form>
          </Stack>
        )}
        {!fixed && s?.mode === 'managed' && (
          <Stack gap="sm">
            <Alert color="orange">{t('mode.managedHint')}</Alert>
            <Text size="sm">{t('mode.managedBy')} <b>{s.managed?.url}</b> · {t('mode.since')} {when(s.managed?.paired_at)}</Text>
            <Switch label={t('mode.keep')} description={t('mode.keepHint')} checked={keep} onChange={(e) => setKeep(e.currentTarget.checked)} />
            {!keep && <Text size="xs" c="dimmed">{s.has_snapshot ? t('mode.restoreHint') : t('mode.emptyHint')}</Text>}
            <Group><Button color="red" variant="light" loading={detach.isPending} onClick={() => modals.openConfirmModal({ title: t('mode.detach'), children: <Text size="sm">{t('mode.detachConfirm')}</Text>, labels: { confirm: t('mode.detach'), cancel: t('common.cancel') }, confirmProps: { color: 'red' }, onConfirm: () => detach.mutate() })}>{t('mode.detach')}</Button></Group>
          </Stack>
        )}
      </Card>

  )
}

export function CoresCard() {
  const { t } = useTranslation()
  const cores = useQuery({ queryKey: ['cores'], queryFn: () => api.get<CoreRelease[]>('/api/cores') })
  return (
      <Card>
        <Title order={5} mb="xs">{t('settings.cores')}</Title>
        <Text size="xs" c="dimmed" mb="sm">{t('settings.coresHint')}</Text>
        <Table>
          <Table.Thead><Table.Tr><Table.Th>{t('inbounds.core')}</Table.Th><Table.Th>{t('settings.version')}</Table.Th><Table.Th>{t('settings.status')}</Table.Th><Table.Th>{t('settings.note')}</Table.Th></Table.Tr></Table.Thead>
          <Table.Tbody>
            {(cores.data ?? []).map((r) => (
              <Table.Tr key={r.Core + r.Version}>
                <Table.Td><Text size="sm" fw={600}>{r.Core}</Text></Table.Td>
                <Table.Td><Text size="sm" ff="monospace">{r.Version}</Text>{r.Installed && <Badge ml={6} size="xs" color="teal">{t('settings.installed')}</Badge>}</Table.Td>
                <Table.Td><Badge color={r.Status === 'tested' ? 'teal' : r.Status === 'broken' ? 'red' : 'yellow'}>{r.Status}</Badge></Table.Td>
                <Table.Td><Text size="xs" c="dimmed">{r.Note}</Text></Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Card>
  )
}

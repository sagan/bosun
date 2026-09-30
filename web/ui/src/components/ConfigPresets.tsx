import { Badge, Button, Card, Code, Group, JsonInput, Modal, Select, Stack, Table, Text, TextInput } from '@mantine/core'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import { toast } from '../lib/notify'

type Preset = { id: number; name: string; kind: string; payload: unknown }
type Preview = { draft: unknown; changes: { field: string; before: unknown; after: unknown }[]; cores?: { options: { name: string; compatible: boolean; reason?: string }[] } }
const base = '/api/config-presets'

export function ConfigPresets({ kind, current, onLoad, affected = [] }: { kind: 'inbound' | 'outbounds' | 'routes'; current: () => unknown; onLoad: (v: unknown) => void; affected?: string[] }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['config-presets'], queryFn: () => api.get<Preset[]>(base) })
  const [id, setID] = useState<string | null>(null)
  const [edit, setEdit] = useState<{ id: number; name: string; body: string } | null>(null)
  const [preview, setPreview] = useState<{ result: Preview; source: string } | null>(null)
  const selected = q.data?.find(p => String(p.id) === id && p.kind === kind)
  const save = useMutation({ mutationFn: async () => {
    if (!edit) return
    const data = { name: edit.name, kind, payload: JSON.parse(edit.body) }
    if (edit.id) await api.put(`${base}/${edit.id}`, data); else await api.post(base, data)
  }, onSuccess: () => { setEdit(null); qc.invalidateQueries({ queryKey: ['config-presets'] }); toast.ok(t('common.saved')) }, onError: toast.err })
  const remove = useMutation({ mutationFn: () => api.del(`${base}/${edit!.id}`), onSuccess: () => { setEdit(null); setID(null); qc.invalidateQueries({ queryKey: ['config-presets'] }) }, onError: toast.err })
  const inspect = useMutation({ mutationFn: async () => {
    const source = JSON.stringify(current())
    return { source, result: await api.post<Preview>(`${base}/preview`, { id: Number(id), current: JSON.parse(source) }) }
  }, onSuccess: setPreview, onError: toast.err })
  const capture = () => { try { const v = current() as Record<string, unknown>; setEdit({ id: 0, name: '', body: JSON.stringify(kind === 'inbound' ? v : v[kind], null, 2) }) } catch (e) { toast.err(e) } }
  const load = () => { try {
    if (JSON.stringify(current()) !== preview!.source) { setPreview(null); toast.err(new Error(t('configPresets.stale'))); return }
    onLoad(preview!.result.draft); setPreview(null)
  } catch (e) { toast.err(e) } }
  return <Card withBorder padding="sm"><Stack gap="xs">
    <Text size="sm" fw={600}>{t(`configPresets.${kind}`)}</Text>
    <Group align="flex-end"><Select style={{ flex: 1, minWidth: 180 }} aria-label={t('configPresets.choose')} placeholder={t('configPresets.choose')} data={(q.data ?? []).filter(p => p.kind === kind).map(p => ({ value: String(p.id), label: p.name }))} value={id} onChange={setID} searchable />
      <Button size="xs" variant="light" disabled={!selected} loading={inspect.isPending} onClick={() => inspect.mutate()}>{t('configPresets.preview')}</Button>
      <Button size="xs" variant="subtle" disabled={!selected} onClick={() => selected && setEdit({ id: selected.id, name: selected.name, body: JSON.stringify(selected.payload, null, 2) })}>{t('configPresets.edit')}</Button>
      <Button size="xs" variant="subtle" onClick={capture}>{t('configPresets.capture')}</Button></Group>
    <Modal opened={!!edit} onClose={() => setEdit(null)} title={t('configPresets.editor')} size="lg"><Stack>
      <Text size="sm" c="dimmed">{t(kind === 'inbound' ? 'configPresets.inboundHint' : 'configPresets.routingHint')}</Text>
      <TextInput label={t('configPresets.name')} value={edit?.name ?? ''} maxLength={100} onChange={e => setEdit(v => v && ({ ...v, name: e.target.value }))} />
      <JsonInput label={t('configPresets.fragment')} description={t('configPresets.fragmentHint')} value={edit?.body ?? ''} onChange={body => setEdit(v => v && ({ ...v, body }))} autosize minRows={6} maxRows={20} formatOnBlur />
      <Group justify="space-between"><Button color="red" variant="light" disabled={!edit?.id} loading={remove.isPending} onClick={() => remove.mutate()}>{t('common.delete')}</Button><Button disabled={!edit?.name.trim()} loading={save.isPending} onClick={() => save.mutate()}>{t('common.save')}</Button></Group>
    </Stack></Modal>
    <Modal opened={!!preview} onClose={() => setPreview(null)} title={t('configPresets.preview')} size="xl"><Stack>
      <Text size="sm">{t(kind === 'inbound' ? 'configPresets.inboundImpact' : 'configPresets.routingImpact')}</Text>
      {affected.length > 0 && <Text size="sm">{t('configPresets.affected')}: {affected.join(', ')}</Text>}
      {preview?.result.cores && <Group gap="xs">{preview.result.cores.options.filter(c => c.compatible).map(c => <Badge key={c.name} variant="light">{c.name}</Badge>)}</Group>}
      <Table.ScrollContainer minWidth={520}><Table striped><Table.Thead><Table.Tr><Table.Th>{t('configPresets.field')}</Table.Th><Table.Th>{t('configPresets.before')}</Table.Th><Table.Th>{t('configPresets.after')}</Table.Th></Table.Tr></Table.Thead><Table.Tbody>{preview?.result.changes.map(c => <Table.Tr key={c.field}><Table.Td>{c.field}</Table.Td><Table.Td><Code block style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(c.before ?? null, null, 2)}</Code></Table.Td><Table.Td><Code block style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(c.after ?? null, null, 2)}</Code></Table.Td></Table.Tr>)}</Table.Tbody></Table></Table.ScrollContainer>
      {!preview?.result.changes.length && <Text c="dimmed">{t('configPresets.noChanges')}</Text>}
      <Button onClick={load}>{t('configPresets.load')}</Button>
    </Stack></Modal>
  </Stack></Card>
}

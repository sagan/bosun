import { KomariCard } from '../components/KomariCard'
import { DStatusCard } from '../components/DStatusCard'
import { Alert, Anchor, Box, Button, Card, Group, SimpleGrid, Stack, Text, TextInput } from '@mantine/core'
import { IconArrowLeft, IconArrowRight, IconSearch } from '@tabler/icons-react'
import { Link, useParams } from 'react-router-dom'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { PageHeader } from '../components/PageHeader'
import { settingsAreas, settingsCatalog } from '../lib/settings-catalog'
import { SettingsDraftBoundary } from '../lib/settings-draft'
import { NodeSettingsCard, ModeCard, CoresCard, type NodeSettingsSection } from '../components/settings/SettingsCards'
import { OverridesCard } from '../components/OverridesCard'
import { BackupCard } from '../components/BackupCard'
import { UpdateCard } from '../components/UpdateCard'
import { useAuth } from '../lib/auth'
import { api } from '../lib/api'

function Editor({ id }: { id: string }) {
  const { me } = useAuth()
  if (id === 'komari') return <KomariCard readOnly={!!me?.fixed || me?.mode === 'managed'} />
  if (id === 'dstatus') return <DStatusCard readOnly={!!me?.fixed || me?.mode === 'managed'} />
  if (id === 'mode') return <ModeCard />
  if (id === 'cores') return <CoresCard />
  if (id === 'backup') return <BackupCard />
  if (id === 'update') return <UpdateCard />
  if (id === 'overrides') return <OverridesCard queryKey={['overrides']} load={() => api.get<Record<string, string>>('/api/overrides')} save={v => api.put('/api/overrides', v)} readOnly={!!me?.fixed || me?.mode === 'managed'} />
  return <NodeSettingsCard section={id as NodeSettingsSection} />
}

export default function SettingsPage() {
  const { t } = useTranslation()
  const { me } = useAuth()
  const id = useParams()['*'] ?? ''
  const [searchState, setSearchState] = useState({ scope: id, value: '' })
  const search = searchState.scope === id ? searchState.value : ''
  const setSearch = (value: string) => setSearchState({ scope: id, value })
  const entry = settingsCatalog.find(e => e.id === id)
  const area = id.startsWith('area/') ? id.slice(5) : undefined
  if (id && !entry && !settingsAreas.some(value => value === area)) return <Stack><Alert color="yellow">{t('workspace.notFound')}</Alert><Anchor component={Link} to="/settings">{t('nav.settings')}</Anchor></Stack>
  if (entry) return <Box maw={1000} mx="auto">
    <Button component={Link} to={`/settings/area/${entry.area}`} variant="subtle" leftSection={<IconArrowLeft size={16} />} mb="sm">{t(`workspace.areas.${entry.area}`)}</Button>
    <PageHeader title={t(entry.titleKey)} subtitle={t(entry.hintKey)} />
    {(me?.fixed || me?.mode === 'managed') && <Alert mb="md">{t('workspace.managedHint')}</Alert>}
    <SettingsDraftBoundary key={entry.id}><Editor id={entry.id} /></SettingsDraftBoundary>
  </Box>
  const term = search.trim().toLocaleLowerCase()
  const entries = settingsCatalog.filter(e => (!area || e.area === area) && `${t(e.titleKey)} ${t(e.hintKey)} ${e.keywords}`.toLocaleLowerCase().includes(term))
  return <Box maw={1000} mx="auto"><PageHeader title={area ? t(`workspace.areas.${area}`) : t('nav.settings')} subtitle={t('workspace.settingsHint')} /><Stack>
    <TextInput aria-label={t('workspace.search')} placeholder={t('workspace.search')} leftSection={<IconSearch size={17} />} value={search} onChange={e => setSearch(e.currentTarget.value)} />
    <Anchor component={Link} to="/account" size="sm">{t('workspace.account')}</Anchor>
    {!area && !term && <SimpleGrid cols={{ base: 1, sm: 2 }}>{settingsAreas.map(group => <Card component={Link} to={`/settings/area/${group}`} key={group} style={{ textDecoration: 'none', color: 'inherit' }}><Group justify="space-between" wrap="nowrap"><Text fw={600}>{t(`workspace.areas.${group}`)}</Text><IconArrowRight size={17} style={{ flexShrink: 0 }} /></Group><Text size="sm" c="dimmed" mt="xs">{settingsCatalog.filter(e => e.area === group).map(e => t(e.titleKey)).join(' · ')}</Text></Card>)}</SimpleGrid>}
    <SimpleGrid cols={{ base: 1, sm: 2 }}>{(area || term ? entries : []).map(e => <Card component={Link} to={`/settings/${e.id}`} key={e.id} style={{ textDecoration: 'none', color: 'inherit' }}><Group justify="space-between" wrap="nowrap"><Text fw={600}>{t(e.titleKey)}</Text><IconArrowRight size={17} style={{ flexShrink: 0 }} /></Group><Text size="sm" c="dimmed" mt="xs" lineClamp={2}>{t(e.hintKey)}</Text></Card>)}</SimpleGrid>
    {area && <Anchor component={Link} to="/settings" size="sm">{t('workspace.allSettings')}</Anchor>}
    {!entries.length && <Text c="dimmed">{t('workspace.noResults')}</Text>}
  </Stack></Box>
}

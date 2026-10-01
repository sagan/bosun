import { ActionIcon, AppShell, Avatar, Badge, Box, Burger, Group, Indicator, Menu, NavLink, ScrollArea, Text, ThemeIcon, Tooltip, UnstyledButton, useMantineColorScheme } from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { IconLayoutDashboard, IconPlugConnected, IconUsers, IconSettings, IconLogout, IconLanguage, IconActivity, IconAnchor, IconSun, IconMoon, IconDotsVertical, IconChevronDown } from '@tabler/icons-react'
import { languages } from '../i18n'
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useAuth } from '../lib/auth'
import { useQuery } from '@tanstack/react-query'
import { api, type UpdateInfo } from '../lib/api'
import { pageBackground } from '../theme'
import { navigation, navigationGroup } from '../lib/navigation'
import { GroupedNavigation } from './GroupedNavigation'

const icons = { overview: IconLayoutDashboard, services: IconPlugConnected, users: IconUsers, monitoring: IconActivity }

export function ModeBadge({ mode, fixed }: { mode: string; fixed?: string }) {
  const { t } = useTranslation()
  if (fixed) return <Tooltip label={t('mode.fixedHint', { driver: fixed })}><Badge color="grape" variant="filled">{t('mode.fixed', { driver: fixed })}</Badge></Tooltip>
  return mode === 'managed'
    ? <Tooltip label={t('mode.managedHint')}><Badge color="orange" variant="filled">{t('mode.managed')}</Badge></Tooltip>
    : <Badge color="teal" variant="light">{t('mode.local')}</Badge>
}

export function Brand({ name, size = 'md' }: { name: string; size?: 'md' | 'lg' }) {
  return (
    <Group gap="xs" wrap="nowrap">
      <ThemeIcon size={size === 'lg' ? 40 : 30} radius="md" variant="filled"><IconAnchor size={size === 'lg' ? 24 : 18} stroke={2} /></ThemeIcon>
      <Text fw={700} size={size === 'lg' ? 'xl' : 'lg'} style={{ letterSpacing: '-0.01em' }}>{name}</Text>
    </Group>
  )
}

export function AppLayout() {
  const [opened, { toggle, close }] = useDisclosure()
  const { t, i18n } = useTranslation()
  const { me, logout } = useAuth()
  const nav = useNavigate()
  const loc = useLocation()
  const { colorScheme, setColorScheme } = useMantineColorScheme()
  const group = navigationGroup(loc.pathname)
  const upd = useQuery({ queryKey: ['update'], queryFn: () => api.get<UpdateInfo>('/api/update'), staleTime: 10 * 60_000, refetchInterval: 30 * 60_000, retry: false })
  const lang = languages.find((l) => l.code === i18n.language) ?? languages[0]
  const dark = colorScheme === 'dark'

  return (
    <AppShell navbar={{ width: 248, breakpoint: 'sm', collapsed: { mobile: !opened } }} header={{ height: 56 }} padding="lg" styles={{ main: { background: pageBackground } }}>
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between" wrap="nowrap">
          <Group gap="sm" wrap="nowrap">
            <Burger aria-label={t('workspace.navigation')} opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
            <UnstyledButton onClick={() => { nav('/'); close() }}><Brand name="bosun" /></UnstyledButton>
          </Group>
          <Group gap="xs" wrap="nowrap" align="center">
            {me && <ModeBadge mode={me.mode} fixed={me.fixed} />}
            {me?.version && (
              <Indicator disabled={!upd.data?.has_update} color="red" size={8} offset={2} processing styles={{ root: { display: 'flex' } }}>
                <Badge variant="light" color="gray" style={{ cursor: 'pointer' }} onClick={() => nav('/settings/update')} title={upd.data?.has_update ? t('update.available', { version: upd.data.latest }) : undefined}>{me.version}</Badge>
              </Indicator>
            )}
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar>
        <AppShell.Section grow component={ScrollArea} type="auto" scrollbarSize={6} px="sm" py="sm">
          <GroupedNavigation groups={navigation} icons={icons} activeGroup={group} onNavigate={close} />
        </AppShell.Section>
        <AppShell.Section p="sm" style={{ borderTop: '1px solid var(--mantine-color-default-border)' }}>
          <NavLink component={Link} to="/settings" label={t('nav.settings')} leftSection={<IconSettings size={18} />} active={group === 'system'} onClick={close} mb="sm" styles={{ root: { borderRadius: 8 } }} />
          <Group justify="space-between" mb="sm" px={4}>
            <Menu shadow="md" width={160}>
              <Menu.Target>
                <UnstyledButton aria-label="language">
                  <Group gap={6}><IconLanguage size={16} stroke={1.7} /><Text size="sm" fw={500}>{lang.label}</Text><IconChevronDown size={14} opacity={0.6} /></Group>
                </UnstyledButton>
              </Menu.Target>
              <Menu.Dropdown>
                {languages.map((l) => <Menu.Item key={l.code} fw={i18n.language === l.code ? 700 : undefined} onClick={() => i18n.changeLanguage(l.code)}>{l.label}</Menu.Item>)}
              </Menu.Dropdown>
            </Menu>
            <ActionIcon variant="subtle" color="gray" aria-label="color scheme" onClick={() => setColorScheme(dark ? 'light' : 'dark')}>{dark ? <IconSun size={18} /> : <IconMoon size={18} />}</ActionIcon>
          </Group>
          <Group gap="sm" wrap="nowrap" p="xs" style={{ border: '1px solid var(--mantine-color-default-border)', borderRadius: 12 }}>
            <Avatar radius="xl" color="brand" variant="light">{(me?.username ?? '?').slice(0, 1).toUpperCase()}</Avatar>
            <Box style={{ flex: 1, minWidth: 0 }}>
              <Text size="sm" fw={600} truncate>{me?.username}</Text>
              <Text size="xs" c="dimmed" truncate>{me ? t(`mode.${me.mode}`) : ''}</Text>
            </Box>
            <Menu shadow="md" position="top-end">
              <Menu.Target><ActionIcon variant="subtle" color="gray" aria-label="account menu"><IconDotsVertical size={18} /></ActionIcon></Menu.Target>
              <Menu.Dropdown>
                <Menu.Item leftSection={<IconSettings size={16} />} onClick={() => { nav('/account'); close() }}>{t('workspace.account')}</Menu.Item>
                <Menu.Item leftSection={<IconLogout size={16} />} color="red" onClick={async () => { await logout(); nav('/login') }}>{t('common.logout')}</Menu.Item>
              </Menu.Dropdown>
            </Menu>
          </Group>
        </AppShell.Section>
      </AppShell.Navbar>

      <AppShell.Main><Outlet /></AppShell.Main>
    </AppShell>
  )
}

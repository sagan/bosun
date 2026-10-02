import { Box, NavLink, Stack, Text } from '@mantine/core'
import type { ComponentType } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import classes from './GroupedNavigation.module.css'

interface Item { to: string; labelKey: string }
interface Section { id: string; labelKey: string; items: Item[] }
export function GroupedNavigation({ groups, icons, onNavigate }: { groups: Section[]; icons: Record<string, ComponentType<{ size?: number; stroke?: number }>>; onNavigate: () => void }) {
  const { t } = useTranslation()
  const { pathname } = useLocation()
  return <Box component="nav" aria-label={t('workspace.navigation')}><Stack gap={16}>{groups.map(group => {
    const Icon = icons[group.id]
    return <Box key={group.id}>
      {group.items.length > 1 && <Text className={classes.heading} px="sm" mb={6}>{t(group.labelKey)}</Text>}
      <Stack gap={2}>{group.items.map(item => { const PageIcon = icons[item.to] ?? Icon; return <NavLink key={item.to} component={Link} to={item.to} label={t(item.labelKey)} active={item.to === pathname} aria-current={item.to === pathname ? 'page' : undefined} onClick={onNavigate} className={classes.link} leftSection={PageIcon && <PageIcon size={18} stroke={1.6} />} /> })}</Stack>
    </Box>
  })}</Stack></Box>
}

import { ActionIcon, Box, Collapse, Group, NavLink, Stack } from '@mantine/core'
import { IconChevronDown } from '@tabler/icons-react'
import { useState, type ComponentType } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

interface Item { to: string; labelKey: string }
interface Section { id: string; labelKey: string; items: Item[] }
export function GroupedNavigation({ groups, icons, activeGroup, onNavigate }: { groups: Section[]; icons: Record<string, ComponentType<{ size?: number; stroke?: number }>>; activeGroup: string; onNavigate: () => void }) {
  const { t } = useTranslation()
  const location = useLocation()
  const [expansion, setExpansion] = useState<{ route: string; groups: Record<string, boolean> }>({ route: '', groups: {} })
  const expanded = expansion.route === location.key ? expansion.groups : {}
  const setExpanded = (update: (previous: Record<string, boolean>) => Record<string, boolean>) => setExpansion({ route: location.key, groups: update(expanded) })
  return <Stack gap={4}>{groups.map(group => {
    const Icon = icons[group.id]
    const opened = expanded[group.id] ?? activeGroup === group.id
    const toggle = () => setExpanded(previous => ({ ...previous, [group.id]: !opened }))
    const currentParams = new URLSearchParams(location.search)
    const exact = group.items.find(item => {
      const [path, search] = item.to.split('?')
      return path === location.pathname && !!search && [...new URLSearchParams(search)].every(([key, value]) => currentParams.get(key) === value)
    }) ?? group.items.find(item => item.to === location.pathname)
    return <Box key={group.id}>
      <Group gap={0} wrap="nowrap">
        <NavLink component={Link} to={group.items[0].to} label={t(group.labelKey)} active={activeGroup === group.id} leftSection={Icon && <Icon size={19} stroke={1.7} />} style={{ flex: 1, minWidth: 0, borderRadius: 8 }} onClick={() => { setExpanded(previous => ({ ...previous, [group.id]: true })); onNavigate() }} />
        {group.items.length > 1 && <ActionIcon variant="subtle" color="gray" aria-label={t(group.labelKey)} aria-expanded={opened} aria-controls={`nav-${group.id}`} onClick={toggle}><IconChevronDown size={15} style={{ transform: opened ? 'rotate(180deg)' : undefined }} /></ActionIcon>}
      </Group>
      {group.items.length > 1 && <Collapse in={opened}><Stack id={`nav-${group.id}`} gap={2} pl="md" pt={4}>{group.items.map(item => <NavLink key={item.to} component={Link} to={item.to} label={t(item.labelKey)} active={exact ? exact.to === item.to : item.to === location.pathname} variant="light" onClick={onNavigate} styles={{ root: { borderRadius: 8 }, label: { fontSize: 13 } }} />)}</Stack></Collapse>}
    </Box>
  })}</Stack>
}

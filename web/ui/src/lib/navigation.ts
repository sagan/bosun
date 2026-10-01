export const navigation = [
  { id: 'overview', labelKey: 'nav.overview', items: [{ to: '/', labelKey: 'nav.overview' }] },
  { id: 'services', labelKey: 'workspace.services', items: [
    { to: '/inbounds', labelKey: 'nav.inbounds' }, { to: '/forwards', labelKey: 'nav.outbound' }, { to: '/templates', labelKey: 'nav.templates' }, { to: '/certificates', labelKey: 'nav.certificates' }, { to: '/settings/subscription', labelKey: 'settings.extraLinks' },
  ] },
  { id: 'users', labelKey: 'nav.users', items: [{ to: '/users', labelKey: 'nav.users' }] },
  { id: 'monitoring', labelKey: 'workspace.monitoring', items: [
    { to: '/probe', labelKey: 'nav.probe' }, { to: '/doctor', labelKey: 'nav.doctor' }, { to: '/logs', labelKey: 'nav.logs' },
  ] },
]
export function navigationGroup(path: string) {
  if (path === '/account') return 'account'
  return navigation.find(group => group.items.some(item => item.to === path))?.id ?? 'system'
}

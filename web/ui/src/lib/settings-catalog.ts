export const settingsAreas = ['node', 'network', 'runtime', 'subscription', 'integrations', 'maintenance'] as const
export const settingsCatalog = [
  { id: 'komari', area: 'integrations', titleKey: 'komari.title', hintKey: 'komari.hint', keywords: 'Komari monitor integration' },
  { id: 'dstatus', area: 'integrations', titleKey: 'dstatus.title', hintKey: 'dstatus.hint', keywords: 'DStatus monitor integration SID' },
  { id: 'node', area: 'node', titleKey: 'workspace.node', hintKey: 'workspace.nodeHint', keywords: 'public host name hostname 地址 名称' },
  { id: 'mode', area: 'node', titleKey: 'mode.title', hintKey: 'workspace.modeHint', keywords: 'Captain pair standalone driver 托管 独立 配对' },
  { id: 'network', area: 'network', titleKey: 'workspace.network', hintKey: 'workspace.networkHint', keywords: 'ACME Cloudflare DNS TLS certificate CIDR decoy 证书 域名 白名单 伪装站' },
  { id: 'runtime', area: 'runtime', titleKey: 'workspace.runtime', hintKey: 'workspace.runtimeHint', keywords: 'speed quota mita 限速 配额' },
  { id: 'subscription', area: 'subscription', titleKey: 'settings.extraLinks', hintKey: 'settings.extraLinksHint', keywords: 'subscription links 订阅 链接' },
  { id: 'overrides', area: 'runtime', titleKey: 'workspace.overrides', hintKey: 'workspace.overridesHint', keywords: 'override advanced config 覆写 高级 配置' },
  { id: 'notifications', area: 'integrations', titleKey: 'settings.telegram', hintKey: 'settings.telegramHint', keywords: 'Telegram bot notification 通知 机器人' },
  { id: 'cores', area: 'maintenance', titleKey: 'settings.cores', hintKey: 'settings.coresHint', keywords: 'core version capability 内核 版本 能力' },
  { id: 'backup', area: 'maintenance', titleKey: 'backup.title', hintKey: 'backup.hint', keywords: 'backup restore 备份 恢复' },
  { id: 'update', area: 'maintenance', titleKey: 'update.title', hintKey: 'workspace.updateHint', keywords: 'upgrade update version 更新 版本' },
]

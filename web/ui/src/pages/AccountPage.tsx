import { Stack } from '@mantine/core'
import { useTranslation } from 'react-i18next'
import { PageHeader } from '../components/PageHeader'
import { AdminAccountCard } from '../components/settings/SettingsCards'
import { TwoFactorCard } from '../components/TwoFactorCard'
import { TokensCard } from '../components/TokensCard'
import { SettingsDraftBoundary } from '../lib/settings-draft'
export default function AccountPage() {
  const { t } = useTranslation()
  return <><PageHeader title={t('workspace.account')} subtitle={t('workspace.accountHint')} /><SettingsDraftBoundary><Stack><AdminAccountCard /><TwoFactorCard /><TokensCard /></Stack></SettingsDraftBoundary></>
}

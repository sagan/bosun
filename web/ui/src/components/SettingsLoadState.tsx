import { Alert, Button, Center, Loader, Stack } from '@mantine/core'
import { useTranslation } from 'react-i18next'

// Never render editable defaults before the existing settings have loaded.
export function SettingsLoadState({ query }: { query: { isError: boolean; refetch: () => unknown } }) {
  const { t } = useTranslation()
  return query.isError
    ? <Alert color="red"><Stack align="flex-start">{t('workspace.loadError')}<Button variant="light" size="xs" onClick={() => query.refetch()}>{t('workspace.retry')}</Button></Stack></Alert>
    : <Center py="xl"><Loader /></Center>
}

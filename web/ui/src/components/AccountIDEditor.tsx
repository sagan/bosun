import { Button, Group, NumberInput, Stack, Text } from '@mantine/core'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import { toast } from '../lib/notify'

export function AccountIDEditor({ id, endpoint, onChanged }: { id: number; endpoint: string; onChanged: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [value, setValue] = useState<number | string>(id)
  const change = useMutation({
    mutationFn: () => api.put(endpoint, { id: Number(value) }),
    onSuccess: () => { toast.ok(t('common.saved')); qc.invalidateQueries(); onChanged() },
    onError: toast.err,
  })
  return <Stack gap={4}>
    <Group align="flex-end" wrap="nowrap">
      <NumberInput flex={1} label={t('accountID.label')} min={1} max={Number.MAX_SAFE_INTEGER} allowDecimal={false} allowNegative={false} value={value} onChange={setValue} />
      <Button type="button" variant="light" loading={change.isPending} disabled={!Number.isSafeInteger(Number(value)) || Number(value) < 1 || Number(value) === id} onClick={() => change.mutate()}>{t('accountID.change')}</Button>
    </Group>
    <Text size="xs" c="dimmed">{t('accountID.hint')}</Text>
  </Stack>
}

import { Alert, Card, Stack, Title } from '@mantine/core'
import { useMutation } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import type { DiagnosticRequest, DiagnosticResult } from '../lib/diagnostics'
import { DiagnosticForm, DiagnosticResultView } from './NetworkDiagnostic'

export function NetworkDiagnosticsCard() {
 const { t } = useTranslation()
 const run = useMutation({ mutationFn: (params: DiagnosticRequest) => api.post<DiagnosticResult>('/api/diagnostics/network', params) })
 return <Card mb="lg"><Stack gap="sm"><Title order={5}>{t('diagnostics.title')}</Title>
  <DiagnosticForm onRun={(v) => run.mutate(v)} pending={run.isPending} />
  {run.isError && <Alert color="red">{run.error.message}</Alert>}
  {run.data && <DiagnosticResultView result={run.data} />}
 </Stack></Card>
}

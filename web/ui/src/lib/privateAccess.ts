// Upgrade the unpublished manual core-only intent without losing explicit consent.
export function normalizePrivateAccess(settings: Record<string, unknown>) {
 const value = settings.private_access
 if (value && typeof value === 'object' && !Array.isArray(value) && (value as Record<string, unknown>).enforcement === 'core_only') {
  return { ...settings, private_access: { ...value, enforcement: 'auto', allow_core_only: true } }
 }
 return settings
}

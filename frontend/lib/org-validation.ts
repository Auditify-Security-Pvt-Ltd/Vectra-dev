/**
 * Organization profile validation.
 *
 * Mirrors backend/services/organization.py and the checks in firestore.rules.
 * Each function returns the normalized value or throws with a message suitable
 * for display next to the field.
 */

export interface OrganizationInput {
  name:    string
  website: string
  phone:   string
}

const HOST_RE  = /^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$/
const PHONE_RE = /^\+?[0-9][0-9 ()-]{5,18}[0-9]$/

export function cleanOrgName(value: string): string {
  const name = value.replace(/\s+/g, ' ').replace(/[<>]/g, '').trim()
  if (name.length < 2 || name.length > 100) {
    throw new Error('Organization name must be 2–100 characters.')
  }
  return name
}

/** Normalize to scheme://host[:port][/path]. Only http(s), no credentials. */
export function cleanWebsite(value: string): string {
  let raw = value.trim()
  if (!raw) throw new Error('Website URL is required.')
  if (!raw.includes('://')) raw = `https://${raw}`

  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new Error('Website URL is not valid.')
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Website must use http or https.')
  }
  if (url.username || url.password || !HOST_RE.test(url.hostname)) {
    throw new Error('Website URL is not valid.')
  }
  const path = url.pathname.replace(/\/+$/, '')
  const normalized = `${url.protocol}//${url.hostname.toLowerCase()}${url.port ? `:${url.port}` : ''}${path}`
  if (normalized.length > 200) throw new Error('Website URL is too long.')
  return normalized
}

export function cleanPhone(value: string): string {
  const phone = value.replace(/\s+/g, ' ').trim()
  if (!PHONE_RE.test(phone)) {
    throw new Error('Enter a valid phone number: digits, spaces, ( ) - and an optional leading +.')
  }
  return phone
}

/** Validates all fields; returns normalized values or a per-field error map. */
export function validateOrganization(
  input: OrganizationInput,
): { value: OrganizationInput; errors: null } | { value: null; errors: Partial<Record<keyof OrganizationInput, string>> } {
  const errors: Partial<Record<keyof OrganizationInput, string>> = {}
  const value = { name: '', website: '', phone: '' }
  const fields: [keyof OrganizationInput, (v: string) => string][] = [
    ['name', cleanOrgName], ['website', cleanWebsite], ['phone', cleanPhone],
  ]
  for (const [key, clean] of fields) {
    try { value[key] = clean(input[key]) } catch (e) { errors[key] = (e as Error).message }
  }
  return Object.keys(errors).length ? { value: null, errors } : { value, errors: null }
}

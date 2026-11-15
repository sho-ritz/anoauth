import type { Verified } from './verifier.js'

export type GrantRole = 'admin' | 'writer' | 'reader'

/** A proof requirement: a verifier type and, optionally, which issuers to trust. */
export interface ProofMatch {
  type: string
  /** Trusted issuer(s): pubkey hex / npub for certificates, issuer URL for OIDC. */
  issuer?: string | string[]
}

/**
 * One admission rule. Rules are evaluated in order; the first that matches decides.
 *
 * - `proof: 'link'`      anyone who has the invite link
 * - `proof: 'approval'`  an owner / admin approves each request by hand
 * - `proof: { type, issuer }` a verified proof (certificate, OIDC…) matching the conditions below.
 *   Listing `email` makes the rule a *reservation* for those people.
 */
export interface Rule {
  proof: 'link' | 'approval' | ProofMatch
  email?: string[]
  emailDomain?: string | string[]
  /** Other attributes that must match, e.g. `{ department: ['sales', 'support'] }`. */
  claims?: Record<string, string | string[]>
  role: GrantRole
  /** Members admitted by this rule must prove again within this many days (proof rules: 90; 0 = never). */
  revalidateDays?: number
}

const list = (v: string | string[] | undefined) => (v === undefined ? undefined : (Array.isArray(v) ? v : [v]).map((x) => x.toLowerCase()))

export function revalidateDaysOf(rule: Rule): number {
  if (typeof rule.proof === 'string') return 0
  return rule.revalidateDays ?? 90
}

/** The verified proof that satisfies a proof rule, if any. */
export function matchProof(rule: Rule, proofs: readonly Verified[], normalizeIssuer: (s: string) => string): Verified | null {
  if (typeof rule.proof === 'string') return null
  const m = rule.proof
  const issuers = list(m.issuer)?.map(normalizeIssuer)
  const emails = list(rule.email)
  const domains = list(rule.emailDomain)
  for (const v of proofs) {
    if (v.type !== m.type) continue
    if (issuers && !issuers.includes(normalizeIssuer(v.issuer))) continue
    const email = typeof v.claims.email === 'string' ? v.claims.email.toLowerCase() : undefined
    if ((emails || domains) && (!email || v.claims.email_verified === false)) continue
    if (emails && !emails.includes(email!)) continue
    if (domains && !domains.includes(email!.split('@')[1] ?? '')) continue
    if (rule.claims && !Object.entries(rule.claims).every(([k, want]) => list(want)!.includes(String(v.claims[k] ?? '').toLowerCase()))) continue
    return v
  }
  return null
}

export function validRule(r: unknown): r is Rule {
  const x = r as Rule
  if (typeof x !== 'object' || x === null || !['admin', 'writer', 'reader'].includes(x.role)) return false
  if (x.proof === 'link' || x.proof === 'approval') return true
  return typeof x.proof === 'object' && x.proof !== null && typeof x.proof.type === 'string'
}

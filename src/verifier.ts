import { finalizeEvent, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import type { NostrEvent } from '@anodb/core'

/** What a verifier proved about the applicant. */
export interface Verified {
  /** Proof type, e.g. `certificate`. */
  type: string
  /** Who vouches: an issuer npub / pubkey hex, an OIDC issuer URL, … */
  issuer: string
  /** Stable id of the person at that issuer (e.g. the email). One subject = one pubkey per space. */
  subject: string
  /** Attributes, e.g. `{ email: 'alice@company.com', department: 'sales' }`. */
  claims: Record<string, unknown>
  /** When the issuer made the statement (ms). */
  issuedAt: number
}

export interface VerifyContext {
  /** anoDB identity (pubkey hex) of the applicant; the proof must be bound to it. */
  identity: string
  /** The link secret (for nonces that bind a proof to one link). */
  secret: string
  now: number
}

/** A proof type. Runs on owner / admin devices only. Return null when the proof does not hold. */
export interface Verifier {
  type: string
  verify(data: unknown, ctx: VerifyContext): Promise<Verified | null>
}

// ---- signed certificates (Nostr events) ----------------------------------------------------

/** "The issuer vouches that pubkey P has these attributes", signed by the issuer's key. */
export const CERTIFICATE_KIND = 7384

export interface CertificateInput {
  /** anoDB identity (pubkey hex) the certificate is about. */
  subject: string
  /** Attributes. `email` (or `sub`) becomes the subject id used for "one person = one key". */
  claims: Record<string, string>
  /** Expiry in ms (optional). */
  expiresAt?: number
  now?: number
}

/** Issue a certificate (an issuer's backend, a company system, a future anoAuth issuer). */
export function issueCertificate(issuerSecretKey: Uint8Array, c: CertificateInput): NostrEvent {
  const now = c.now ?? Date.now()
  const tags = [['p', c.subject], ...Object.entries(c.claims).map(([k, v]) => ['claim', k, v])]
  if (c.expiresAt !== undefined) tags.push(['expiration', String(Math.floor(c.expiresAt / 1000))])
  return finalizeEvent({ kind: CERTIFICATE_KIND, created_at: Math.floor(now / 1000), tags, content: '' }, issuerSecretKey) as NostrEvent
}

export const issuerPubkey = (issuerSecretKey: Uint8Array) => getPublicKey(issuerSecretKey)

/** Verifies certificates offline. Which issuers to trust is decided by the rules. */
export function certificateVerifier(): Verifier {
  return {
    type: 'certificate',
    async verify(data, ctx) {
      const e = data as NostrEvent
      if (typeof e !== 'object' || e === null || e.kind !== CERTIFICATE_KIND || !verifyEvent(e)) return null
      if (e.tags.find((t) => t[0] === 'p')?.[1] !== ctx.identity) return null // bound to the applicant
      const exp = e.tags.find((t) => t[0] === 'expiration')?.[1]
      if (exp !== undefined && Number(exp) * 1000 <= ctx.now) return null
      if (e.created_at * 1000 > ctx.now + 5 * 60_000) return null
      const claims: Record<string, unknown> = {}
      for (const t of e.tags) if (t[0] === 'claim' && typeof t[1] === 'string' && typeof t[2] === 'string') claims[t[1]] = t[2]
      const subject = String(claims.email ?? claims.sub ?? ctx.identity).toLowerCase()
      return { type: 'certificate', issuer: e.pubkey, subject, claims, issuedAt: e.created_at * 1000 }
    },
  }
}

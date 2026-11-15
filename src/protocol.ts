import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js'
import * as nip44 from 'nostr-tools/nip44'
import { finalizeEvent, generateSecretKey, verifyEvent } from 'nostr-tools/pure'
import type { NostrEvent } from '@anodb/core'

/** Envelope carrying a join / renewal request to the admins (regular, stored kind). */
export const REQUEST_KIND = 7383
/** Routing tag name (same single-letter tag anoDB uses, so relays index it). */
export const TAG = 'n'

export const sha256Hex = (s: string) => bytesToHex(sha256(utf8ToBytes(s)))
export const randomHex = (bytes: number) => bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)))
export const h32 = (s: string) => sha256Hex(s).slice(0, 32)

/** Only holders of the secret can compute the tag or read the envelope. */
export const secretTag = (secret: string) => h32(`anoauth/v1/tag/${secret}`)
const secretKey = (secret: string) => sha256(utf8ToBytes(`anoauth/v1/key/${secret}`))

export interface ProofEnvelope {
  /** Verifier type, e.g. `certificate`, `oidc`. */
  type: string
  data: unknown
}

export interface RequestPayload {
  v: 1
  t: 'join' | 'renew'
  /** Space the request is for. */
  space: string
  /** anoDB identity (pubkey hex) of the applicant. */
  identity: string
  /** The applicant's device delegations (`db.deviceDelegations()`). */
  devices: NostrEvent[]
  name: string
  proofs: ProofEnvelope[]
}

export function sealRequest(secret: string, payload: RequestPayload, now: number): NostrEvent {
  return finalizeEvent(
    {
      kind: REQUEST_KIND,
      created_at: Math.floor(now / 1000),
      tags: [[TAG, secretTag(secret)]],
      content: nip44.encrypt(JSON.stringify(payload), secretKey(secret)),
    },
    generateSecretKey(), // throwaway: relays learn nothing about the applicant
  ) as NostrEvent
}

const HEX64 = /^[0-9a-f]{64}$/

export function openRequest(secret: string, e: NostrEvent): RequestPayload | null {
  if (e.kind !== REQUEST_KIND || e.content.length > 200_000 || !verifyEvent(e)) return null
  let p: unknown
  try {
    p = JSON.parse(nip44.decrypt(e.content, secretKey(secret)))
  } catch {
    return null
  }
  const r = p as Partial<RequestPayload>
  if (r?.v !== 1 || (r.t !== 'join' && r.t !== 'renew')) return null
  if (typeof r.space !== 'string' || typeof r.identity !== 'string' || !HEX64.test(r.identity)) return null
  if (!Array.isArray(r.devices) || !Array.isArray(r.proofs)) return null
  return {
    v: 1,
    t: r.t,
    space: r.space,
    identity: r.identity,
    devices: r.devices.slice(0, 20) as NostrEvent[],
    name: typeof r.name === 'string' ? r.name.slice(0, 64) : '',
    proofs: r.proofs.filter((x): x is ProofEnvelope => typeof x === 'object' && x !== null && typeof (x as ProofEnvelope).type === 'string').slice(0, 5),
  }
}

// ---- invite links ---------------------------------------------------------------------------

export interface ParsedLink {
  appId: string
  space: string
  secret: string
  /** Proof types the admins accept, e.g. `['certificate', 'oidc']` (a hint for the join screen). */
  accepts: string[]
}

export function formatLink(l: ParsedLink): string {
  const q = new URLSearchParams({ app: l.appId, sp: l.space, s: l.secret })
  if (l.accepts.length) q.set('p', l.accepts.join(','))
  return `anoauth://join?${q.toString()}`
}

/** Accepts `anoauth://join?…` or an app URL carrying it as `#anoauth=…`. */
export function parseLink(text: string): ParsedLink | null {
  let t = text.trim()
  if (!t.startsWith('anoauth://')) {
    try {
      const v = new URLSearchParams(new URL(t).hash.replace(/^#/, '')).get('anoauth')
      if (!v) return null
      t = v
    } catch {
      return null
    }
  }
  let u: URL
  try {
    u = new URL(t)
  } catch {
    return null
  }
  const q = u.searchParams
  const secret = q.get('s') ?? ''
  const space = q.get('sp') ?? ''
  const appId = q.get('app') ?? ''
  if (u.protocol !== 'anoauth:' || u.host !== 'join' || !/^[0-9a-f]{32}$/.test(secret) || !space || !appId) return null
  return { appId, space, secret, accepts: (q.get('p') ?? '').split(',').filter(Boolean) }
}

/** `https://your-app/#anoauth=…`: opening it starts the join screen of your app. */
export function toAppLink(uri: string, base?: string): string {
  const b = base ?? (typeof location !== 'undefined' ? `${location.origin}${location.pathname}` : '')
  return b ? `${b}#anoauth=${encodeURIComponent(uri)}` : uri
}

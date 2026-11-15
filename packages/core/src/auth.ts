import { type AnoDB, DEFAULT_RELAYS, type Invitation, type NostrEvent, RelayPool, type RelayPoolOptions, type Role } from '@anodb/core'
import * as nip19 from 'nostr-tools/nip19'
import { type ParsedLink, type ProofEnvelope, REQUEST_KIND, proofNonce, type RequestPayload, TAG, formatLink, h32, openRequest, parseLink, randomHex, sealRequest, secretTag } from './protocol.js'
import { type GrantRole, type Rule, matchProof, revalidateDaysOf, validRule } from './rules.js'
import { type Verified, type Verifier, certificateVerifier } from './verifier.js'

// biome-ignore lint/suspicious/noExplicitAny: works with any app schema that includes anoauthTables
type DB = AnoDB<any>

export interface AdmissionRequest {
  space: string
  identity: string
  name: string
  /** Proofs that verified. */
  proofs: Verified[]
}

export interface AnoAuthOptions {
  /** Relays for join requests. Default: anoDB's DEFAULT_RELAYS. */
  relays?: readonly string[]
  relayOptions?: RelayPoolOptions
  /** Extra proof types (e.g. `oidcVerifier()` from @anoauth/oidc). Certificates are built in. */
  verifiers?: Verifier[]
  /**
   * Custom decision, run before the rules on owner / admin devices: return a role to admit,
   * `null` to refuse, `undefined` to fall through to the rules.
   */
  check?: (req: AdmissionRequest) => GrantRole | null | undefined | Promise<GrantRole | null | undefined>
  /** How often owner / admin devices remove members whose proof is overdue. Default 1 h. */
  sweepIntervalMs?: number
  now?: () => number
}

export interface StoredRule extends Rule {
  id: string
  /** False when a rule granting `admin` was last written by someone other than the owner (ignored). */
  active: boolean
}

export interface LinkInfo {
  id: string
  uri: string
  accepts: string[]
  expiresAt: number | null
  singleUse: boolean
  usedBy: string | null
  revoked: boolean
}

export interface JoinRequestInfo {
  id: string
  space: string
  identity: string
  npub: string
  name: string
  role: GrantRole
  /** `pending`: waits for approval. `conflict`: this person is already a member with another key. */
  status: 'pending' | 'conflict' | 'rejected' | 'approved'
  proof: Verified | null
}

export interface AdmissionInfo {
  identity: string
  proofType: string
  issuer: string
  subject: string
  provedAt: number
  revalidateDays: number
  admittedBy: string | null
}

const DAY = 86_400_000
/** Admin spaces are named with this prefix; hide them from lists of rooms / spaces. */
export const ADMIN_PREFIX = 'anoauth-admin:'
export const isAdminSpace = (s: { name: string }) => s.name.startsWith(ADMIN_PREFIX)
const MANAGERS = new Set<Role | undefined>(['owner', 'admin'])
const toHex = (s: string) => {
  if (s.startsWith('npub1')) {
    const d = nip19.decode(s)
    if (d.type === 'npub') return d.data
  }
  return s.toLowerCase()
}
const parseJson = <T>(v: unknown, fallback: T): T => {
  if (typeof v !== 'string') return (v as T) ?? fallback
  try {
    return JSON.parse(v) as T
  } catch {
    return fallback
  }
}

interface Route {
  kind: 'link' | 'renew'
  target: string
  admin: string
  secret: string
  link?: LinkRow
}
interface LinkRow {
  id: string
  secret: string
  accepts: string
  expiresAt: number | null
  singleUse: number
  usedBy: string | null
  revoked: number
}

/**
 * Decides who may join a shared anoDB space and admits them with `db.addMember`.
 * Create one per database: `const auth = createAnoAuth(db)`.
 */
export class AnoAuth {
  readonly db: DB
  readonly #pool: RelayPool
  readonly #verifiers = new Map<string, Verifier>()
  readonly #opts: AnoAuthOptions
  readonly #now: () => number
  readonly #seen = new Set<string>()
  readonly #off: Array<() => void> = []
  #routes = new Map<string, Route>()
  #routeKey = ''
  #unsub: (() => void) | null = null
  #refreshing = false
  #dirty = false
  #timer: ReturnType<typeof setInterval> | null = null
  #closed = false

  constructor(db: DB, opts: AnoAuthOptions = {}) {
    this.db = db
    this.#opts = opts
    this.#now = opts.now ?? Date.now
    this.#pool = new RelayPool(opts.relays ?? DEFAULT_RELAYS, opts.relayOptions)
    for (const v of [certificateVerifier(), ...(opts.verifiers ?? [])]) this.#verifiers.set(v.type, v)
  }

  /** Start listening (called by createAnoAuth). */
  async start(): Promise<void> {
    this.#pool.connect()
    this.#off.push(this.db.onChange(() => this.#scheduleRefresh()))
    this.#off.push(this.db.onInvitation((i: Invitation) => void this.#onInvitation(i).catch(() => {})))
    for (const i of this.db.invitations()) await this.#onInvitation(i)
    await this.#refresh()
    this.#timer = setInterval(() => void this.sweep().catch(() => {}), this.#opts.sweepIntervalMs ?? 3600_000)
    ;(this.#timer as { unref?: () => void }).unref?.()
  }

  close(): void {
    this.#closed = true
    for (const f of this.#off.splice(0)) f()
    this.#unsub?.()
    if (this.#timer) clearInterval(this.#timer)
    this.#pool.close()
  }

  // ---- admins: setup ---------------------------------------------------------------------

  /** Guard a space with anoAuth (owner only). Creates its admin space; returns the admin space id. */
  async enable(space: string): Promise<string> {
    if (this.db.roleIn(space) !== 'owner') throw new Error('anoAuth: only the owner can enable anoAuth for a space')
    const existing = await this.adminSpaceOf(space)
    if (existing) return existing
    const admin = await this.db.createSpace(`${ADMIN_PREFIX}${space}`)
    await this.db.execute('INSERT INTO "anoauthGuard" (space, target) VALUES (?, ?)', [admin, space]) // id names the owner → createdBy
    const ch = await this.db.execute('SELECT id FROM "anoauthChannel" WHERE space = ? AND id = ?', [space, 'renewal'])
    if (ch.length === 0) await this.db.execute('INSERT INTO "anoauthChannel" (space, id, secret) VALUES (?, ?, ?)', [space, 'renewal', randomHex(16)])
    await this.#syncAdmins(space, admin)
    await this.#refresh()
    return admin
  }

  /** The admin space guarding `space`, if this device can see it. */
  async adminSpaceOf(space: string): Promise<string | null> {
    return (await this.#guards()).find((g) => g.target === space)?.admin ?? null
  }

  async #guards(): Promise<Array<{ admin: string; target: string }>> {
    const rows = (await this.#rows<{ space: string; target: string; createdBy: string | null }>('SELECT space, target, "createdBy" FROM "anoauthGuard"'))
    return rows
      .filter((r) => r.createdBy !== null && r.createdBy === this.#ownerOf(r.target) && this.db.spaces().some((s) => s.id === r.space && s.status === 'active'))
      .map((r) => ({ admin: r.space, target: r.target }))
  }

  // ---- rules -----------------------------------------------------------------------------

  /** Replace the rules of a space (owner / admin; rules granting `admin`: owner only). */
  async setRules(space: string, rules: readonly Rule[]): Promise<void> {
    const admin = await this.#requireAdmin(space)
    for (const r of rules) if (!validRule(r)) throw new Error(`anoAuth: invalid rule ${JSON.stringify(r)}`)
    if (rules.some((r) => r.role === 'admin') && this.db.roleIn(space) !== 'owner') throw new Error('anoAuth: only the owner can add rules that grant admin')
    await this.db.execute('DELETE FROM "anoauthRules" WHERE space = ?', [admin])
    for (const [i, r] of rules.entries()) {
      await this.db.execute('INSERT INTO "anoauthRules" (space, id, position, rule) VALUES (?, ?, ?, ?)', [admin, `${i}-${randomHex(6)}`, i, JSON.stringify(r)])
    }
  }

  async rules(space: string): Promise<StoredRule[]> {
    const admin = await this.adminSpaceOf(space)
    if (!admin) return []
    const owner = this.#ownerOf(space)
    return (await this.#rows<{ id: string; rule: string; updatedBy: string | null }>('SELECT id, rule, "updatedBy" FROM "anoauthRules" WHERE space = ? ORDER BY position, id', [admin])).flatMap((row) => {
      const r = parseJson<unknown>(row.rule, null)
      if (!validRule(r)) return []
      return [{ ...r, id: row.id, active: r.role !== 'admin' || row.updatedBy === owner }]
    })
  }

  // ---- links ---------------------------------------------------------------------------------

  /**
   * An invite link (owner / admin). Anyone may open it; the rules decide who gets in.
   * Default: reusable, expires in 30 days. `expiresInMs: null` = never.
   */
  async createLink(space: string, opts: { expiresInMs?: number | null; singleUse?: boolean; accepts?: string[] } = {}): Promise<string> {
    const admin = await this.#requireAdmin(space)
    const secret = randomHex(16)
    const accepts = opts.accepts ?? [...new Set((await this.rules(space)).flatMap((r) => (typeof r.proof === 'object' ? [r.proof.type] : [])))]
    const expires = opts.expiresInMs === null ? null : this.#now() + (opts.expiresInMs ?? 30 * DAY)
    await this.db.execute('INSERT INTO "anoauthLinks" (space, id, secret, accepts, "expiresAt", "singleUse", revoked) VALUES (?, ?, ?, ?, ?, ?, 0)', [
      admin,
      secretTag(secret),
      secret,
      JSON.stringify(accepts),
      expires,
      opts.singleUse ? 1 : 0,
    ])
    await this.#refresh()
    return formatLink({ appId: this.db.appId, space, secret, accepts })
  }

  async links(space: string): Promise<LinkInfo[]> {
    const admin = await this.adminSpaceOf(space)
    if (!admin) return []
    return (await this.#rows<LinkRow>('SELECT id, secret, accepts, "expiresAt", "singleUse", "usedBy", revoked FROM "anoauthLinks" WHERE space = ?', [admin])).map((l) => {
      const accepts = parseJson<string[]>(l.accepts, [])
      return { id: l.id, uri: formatLink({ appId: this.db.appId, space, secret: l.secret, accepts }), accepts, expiresAt: l.expiresAt, singleUse: l.singleUse === 1, usedBy: l.usedBy, revoked: l.revoked === 1 }
    })
  }

  async revokeLink(space: string, link: string): Promise<void> {
    const admin = await this.#requireAdmin(space)
    const parsed = parseLink(link)
    const id = parsed ? secretTag(parsed.secret) : link
    await this.db.execute('UPDATE "anoauthLinks" SET revoked = 1 WHERE space = ? AND id = ?', [admin, id])
  }

  // ---- requests & admissions -----------------------------------------------------------------

  async requests(space?: string): Promise<JoinRequestInfo[]> {
    const out: JoinRequestInfo[] = []
    for (const g of await this.#guards()) {
      if (space && g.target !== space) continue
      for (const r of (await this.#rows<{ id: string; identity: string; name: string; role: string; status: string; proof: string | null }>(
        `SELECT id, identity, name, role, status, proof FROM "anoauthRequests" WHERE space = ? AND status IN ('pending', 'conflict') ORDER BY "createdAt"`,
        [g.admin],
      ))) {
        out.push({ id: r.id, space: g.target, identity: r.identity, npub: nip19.npubEncode(r.identity), name: r.name, role: r.role as GrantRole, status: r.status as JoinRequestInfo['status'], proof: parseJson<Verified | null>(r.proof, null) })
      }
    }
    return out
  }

  /** Admit a pending request. For a `conflict`, the member's old key is removed and replaced. */
  async approve(id: string): Promise<void> {
    const found = await this.#findRequest(id)
    if (!found) throw new Error('anoAuth: unknown request')
    const { g, r } = found
    await this.#requireAdmin(g.target)
    if (r.status === 'conflict' && r.subjectKey) {
      const old = (await this.#rows<{ identity: string }>('SELECT identity FROM "anoauthAdmissions" WHERE space = ? AND id = ?', [g.admin, r.subjectKey]))[0]
      if (old && this.db.members(g.target).some((m) => m.identity === old.identity)) await this.db.removeMember(g.target, old.identity)
      await this.db.execute('DELETE FROM "anoauthAdmissions" WHERE space = ? AND id = ?', [g.admin, r.subjectKey])
    }
    const proof = parseJson<(Verified & { revalidateDays?: number }) | null>(r.proof, null)
    const link = (await this.#rows<LinkRow>('SELECT id, secret, accepts, "expiresAt", "singleUse", "usedBy", revoked FROM "anoauthLinks" WHERE space = ? AND id = ?', [g.admin, r.link]))[0]
    await this.#admit(g, r.identity, parseJson<NostrEvent[]>(r.devices, []), r.role as GrantRole, proof, proof?.revalidateDays ?? 0, link, true)
  }

  async reject(id: string): Promise<void> {
    const found = await this.#findRequest(id)
    if (!found) throw new Error('anoAuth: unknown request')
    await this.#requireAdmin(found.g.target)
    await this.db.execute(`UPDATE "anoauthRequests" SET status = 'rejected' WHERE space = ? AND id = ?`, [found.g.admin, id])
  }

  async admissions(space: string): Promise<AdmissionInfo[]> {
    const admin = await this.adminSpaceOf(space)
    if (!admin) return []
    return (await this.#rows<AdmissionInfo>('SELECT identity, "proofType", issuer, subject, "provedAt", "revalidateDays", "createdBy" AS "admittedBy" FROM "anoauthAdmissions" WHERE space = ?', [admin]))
  }

  /** Remove members whose proof is overdue (runs periodically on owner / admin devices). */
  async sweep(): Promise<number> {
    let removed = 0
    const now = this.#now()
    for (const g of await this.#guards()) {
      if (!MANAGERS.has(this.db.roleIn(g.target))) continue
      const due = (await this.#rows<{ id: string; identity: string; provedAt: number; revalidateDays: number }>(
        'SELECT id, identity, "provedAt", "revalidateDays" FROM "anoauthAdmissions" WHERE space = ? AND "revalidateDays" > 0',
        [g.admin],
      )).filter((a) => a.provedAt + a.revalidateDays * DAY < now)
      for (const a of due) {
        const m = this.db.members(g.target).find((x) => x.identity === a.identity)
        if (m && m.role !== 'owner') {
          try {
            await this.db.removeMember(g.target, a.identity)
            removed++
          } catch {
            continue // e.g. an admin cannot remove another admin; the owner's device will
          }
        }
        await this.db.execute('DELETE FROM "anoauthAdmissions" WHERE space = ? AND id = ?', [g.admin, a.id])
      }
    }
    return removed
  }

  // ---- applicants ------------------------------------------------------------------------------

  /** Parse an invite link (to show what proof the space accepts). */
  parseLink(link: string): ParsedLink | null {
    return parseLink(link)
  }

  /**
   * Ask to join via an invite link. When an owner / admin device admits you, the invitation is
   * accepted automatically. `proofs`: e.g. `[{ type: 'certificate', data: certEvent }]`.
   */
  async requestJoin(link: string, opts: { name?: string; proofs?: ProofEnvelope[] } = {}): Promise<{ space: string }> {
    const l = parseLink(link)
    if (!l) throw new Error('anoAuth: not an invite link')
    if (l.appId !== this.db.appId) throw new Error('anoAuth: this invite link is for another app')
    if (this.db.spaces().some((s) => s.id === l.space && s.status === 'active')) throw new Error('anoAuth: you are already a member of this space')
    await this.db.execute('INSERT INTO "anoauthPending" (space, id, target) VALUES (?, ?, ?) ON CONFLICT (space, id) DO UPDATE SET target = excluded.target', [
      this.db.personalSpace,
      l.space,
      l.space,
    ])
    await this.#send(l.secret, { v: 1, t: 'join', space: l.space, identity: this.db.pubkey, devices: this.db.deviceDelegations(), name: opts.name ?? '', proofs: opts.proofs ?? [] })
    return { space: l.space }
  }

  /** Prove again (members admitted by an external proof must do so before it is overdue). */
  async renew(space: string, proofs: ProofEnvelope[]): Promise<void> {
    const ch = (await this.#rows<{ secret: string }>('SELECT secret FROM "anoauthChannel" WHERE space = ? AND id = ?', [space, 'renewal']))[0]
    if (!ch) throw new Error('anoAuth: this space is not guarded by anoAuth')
    await this.#send(ch.secret, { v: 1, t: 'renew', space, identity: this.db.pubkey, devices: this.db.deviceDelegations(), name: '', proofs })
  }

  /**
   * The nonce to put into an external proof (OIDC `nonce`) for an invite link, or for renewing
   * membership of a space.
   */
  async nonceFor(linkOrSpace: string): Promise<string> {
    const l = parseLink(linkOrSpace)
    if (l) return proofNonce(this.db.pubkey, l.secret)
    const ch = (await this.#rows<{ secret: string }>('SELECT secret FROM "anoauthChannel" WHERE space = ? AND id = ?', [linkOrSpace, 'renewal']))[0]
    if (!ch) throw new Error('anoAuth: not an invite link, and the space is not guarded by anoAuth')
    return proofNonce(this.db.pubkey, ch.secret)
  }

  /** Spaces this identity asked to join and that have not admitted it yet. */
  async pending(): Promise<string[]> {
    return (await this.#rows<{ id: string }>('SELECT id FROM "anoauthPending" WHERE space = ?', [this.db.personalSpace])).map((r) => r.id)
  }

  async #send(secret: string, payload: RequestPayload): Promise<void> {
    const e = sealRequest(secret, payload, this.#now())
    // Some relays refuse unknown pubkeys or are down: wait for a few connections, then retry until one stores it.
    const want = Math.min(2, this.#pool.relays.length)
    const start = Date.now()
    while (this.#pool.connected().length < want && Date.now() - start < 6000) await new Promise((r) => setTimeout(r, 50))
    for (let attempt = 0; attempt < 5; attempt++) {
      const res = await this.#pool.publish(e)
      if ([...res.values()].some((r) => r.outcome === 'ok')) return
      await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)))
    }
    throw new Error('anoAuth: no relay accepted the request; try again')
  }

  async #onInvitation(i: Invitation): Promise<void> {
    if (this.#closed) return
    if (i.name.startsWith(ADMIN_PREFIX)) {
      const target = i.name.slice(ADMIN_PREFIX.length)
      if (MANAGERS.has(this.db.roleIn(target)) && i.from === this.#ownerOf(target)) await this.db.acceptInvitation(i.space).catch(() => {})
      return
    }
    if ((await this.pending()).includes(i.space)) {
      await this.db.acceptInvitation(i.space).catch(() => {})
      await this.db.execute('DELETE FROM "anoauthPending" WHERE space = ? AND id = ?', [this.db.personalSpace, i.space])
    }
  }

  // ---- processing (owner / admin devices) -----------------------------------------------------

  #scheduleRefresh(): void {
    if (this.#closed) return
    if (this.#refreshing) {
      this.#dirty = true
      return
    }
    queueMicrotask(() => void this.#refresh().catch(() => {}))
  }

  async #refresh(): Promise<void> {
    if (this.#closed || this.#refreshing) return
    this.#refreshing = true
    try {
      do {
        this.#dirty = false
        const routes = new Map<string, Route>()
        for (const g of await this.#guards()) {
          if (!MANAGERS.has(this.db.roleIn(g.target))) continue
          if (this.db.roleIn(g.target) === 'owner') await this.#syncAdmins(g.target, g.admin)
          for (const l of (await this.#rows<LinkRow>('SELECT id, secret, accepts, "expiresAt", "singleUse", "usedBy", revoked FROM "anoauthLinks" WHERE space = ?', [g.admin]))) {
            if (l.revoked === 1 || (l.expiresAt !== null && l.expiresAt <= this.#now())) continue
            routes.set(secretTag(l.secret), { kind: 'link', target: g.target, admin: g.admin, secret: l.secret, link: l })
          }
          const ch = (await this.#rows<{ secret: string }>('SELECT secret FROM "anoauthChannel" WHERE space = ? AND id = ?', [g.target, 'renewal']))[0]
          if (ch) routes.set(secretTag(ch.secret), { kind: 'renew', target: g.target, admin: g.admin, secret: ch.secret })
        }
        this.#routes = routes
        const key = [...routes.keys()].sort().join(',')
        if (key !== this.#routeKey) {
          this.#routeKey = key
          this.#unsub?.()
          this.#unsub = routes.size
            ? this.#pool.subscribe(() => (this.#routes.size ? [{ kinds: [REQUEST_KIND], [`#${TAG}`]: [...this.#routes.keys()] }] : null), {
                onEvent: (_relay, e) => void this.#onEvent(e).catch(() => {}),
              })
            : null
        }
      } while (this.#dirty)
    } finally {
      this.#refreshing = false
    }
  }

  /** The owner keeps the admin space's members equal to the space's admins. */
  async #syncAdmins(target: string, admin: string): Promise<void> {
    if (this.db.roleIn(admin) !== 'owner') return
    const want = new Set(this.db.members(target).filter((m) => m.role === 'admin').map((m) => m.identity))
    const have = this.db.members(admin)
    for (const id of want) if (!have.some((m) => m.identity === id)) await this.db.addMember(admin, id, 'writer').catch(() => {})
    for (const m of have) if (m.role !== 'owner' && !want.has(m.identity)) await this.db.removeMember(admin, m.identity).catch(() => {})
  }

  async #onEvent(e: NostrEvent): Promise<void> {
    if (this.#closed || this.#seen.has(e.id)) return
    this.#seen.add(e.id)
    const tag = e.tags.find((t) => t[0] === TAG)?.[1]
    const route = tag ? this.#routes.get(tag) : undefined
    if (!route) return
    const p = openRequest(route.secret, e)
    if (!p || p.space !== route.target) return
    if (route.kind === 'renew') return this.#renew(route, p)
    if (p.t === 'join') return this.#join(route, p)
  }

  async #verify(p: RequestPayload, secret: string): Promise<Verified[]> {
    const out: Verified[] = []
    for (const pr of p.proofs) {
      const v = this.#verifiers.get(pr.type)
      if (!v) continue
      const r = await v.verify(pr.data, { identity: p.identity, secret, now: this.#now() }).catch(() => null)
      if (r) out.push(r)
    }
    return out
  }

  async #join(route: Route, p: RequestPayload): Promise<void> {
    const l = route.link!
    if (l.singleUse === 1 && l.usedBy && l.usedBy !== p.identity) return
    if (this.db.members(route.target).some((m) => m.identity === p.identity)) return
    const g = { admin: route.admin, target: route.target }
    const verified = await this.#verify(p, route.secret)
    const d = await this.#decide(g.target, { space: g.target, identity: p.identity, name: p.name, proofs: verified })
    const reqId = h32(`${g.target}|${p.identity}`)
    const existing = (await this.#rows<{ status: string }>('SELECT status FROM "anoauthRequests" WHERE space = ? AND id = ?', [g.admin, reqId]))[0]
    if (!d) {
      if (!existing) await this.#putRequest(g.admin, reqId, l.id, p, 'reader', 'rejected', null, null)
      return
    }
    if (d.approval) {
      if (!existing || existing.status === 'rejected') await this.#putRequest(g.admin, reqId, l.id, p, d.role, 'pending', null, null)
      return
    }
    const proof = d.proof ? { ...d.proof, revalidateDays: d.revalidateDays } : null
    const subjectKey = this.#subjectKey(d.proof)
    if (subjectKey) {
      const holder = (await this.#rows<{ identity: string }>('SELECT identity FROM "anoauthAdmissions" WHERE space = ? AND id = ?', [g.admin, subjectKey]))[0]
      if (holder && holder.identity !== p.identity && this.db.members(g.target).some((m) => m.identity === holder.identity)) {
        // One person = one key: an admin must confirm replacing the old key.
        await this.#putRequest(g.admin, reqId, l.id, p, d.role, 'conflict', proof, subjectKey)
        return
      }
    }
    if (d.role === 'admin' && this.db.roleIn(g.target) !== 'owner') return // the owner's device admits admins
    await this.#putRequest(g.admin, reqId, l.id, p, d.role, 'pending', proof, subjectKey)
    await this.#admit(g, p.identity, p.devices, d.role, d.proof, d.revalidateDays, l, false)
  }

  async #decide(target: string, req: AdmissionRequest): Promise<{ role: GrantRole; approval?: boolean; proof: Verified | null; revalidateDays: number } | null> {
    const custom = await this.#opts.check?.(req)
    if (custom === null) return null
    if (custom) return { role: custom, proof: req.proofs[0] ?? null, revalidateDays: req.proofs[0] ? 90 : 0 }
    for (const r of await this.rules(target)) {
      if (!r.active) continue
      if (r.proof === 'link') return { role: r.role, proof: null, revalidateDays: 0 }
      if (r.proof === 'approval') return { role: r.role, approval: true, proof: null, revalidateDays: 0 }
      const v = matchProof(r, req.proofs, toHex)
      if (v) return { role: r.role, proof: v, revalidateDays: revalidateDaysOf(r) }
    }
    return null
  }

  #subjectKey(v: Verified | null): string | null {
    return v ? h32(`${v.type}|${toHex(v.issuer)}|${v.subject}`) : null
  }

  async #admit(
    g: { admin: string; target: string },
    identity: string,
    devices: NostrEvent[],
    role: GrantRole,
    proof: Verified | null,
    revalidateDays: number,
    link: LinkRow | undefined,
    manual: boolean,
  ): Promise<void> {
    if (role === 'admin' && this.db.roleIn(g.target) !== 'owner') {
      if (manual) throw new Error('anoAuth: only the owner can admit an admin')
      return
    }
    if (!this.db.members(g.target).some((m) => m.identity === identity)) await this.db.addMember(g.target, identity, role, { devices })
    const id = this.#subjectKey(proof) ?? h32(`id|${identity}`)
    await this.db.execute(
      `INSERT INTO "anoauthAdmissions" (space, id, identity, "proofType", issuer, subject, "provedAt", "revalidateDays") VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (space, id) DO UPDATE SET identity = excluded.identity, "provedAt" = excluded."provedAt", "revalidateDays" = excluded."revalidateDays"`,
      [g.admin, id, identity, proof?.type ?? (manual ? 'approval' : 'link'), proof ? toHex(proof.issuer) : '', proof?.subject ?? identity, this.#now(), revalidateDays],
    )
    if (link && link.singleUse === 1) await this.db.execute('UPDATE "anoauthLinks" SET "usedBy" = ? WHERE space = ? AND id = ?', [identity, g.admin, link.id])
    await this.db.execute(`UPDATE "anoauthRequests" SET status = 'approved' WHERE space = ? AND identity = ?`, [g.admin, identity])
  }

  async #renew(route: Route, p: RequestPayload): Promise<void> {
    if (!this.db.members(route.target).some((m) => m.identity === p.identity)) return
    const verified = await this.#verify(p, route.secret)
    const keys = new Set(verified.map((v) => this.#subjectKey(v)))
    const mine = (await this.#rows<{ id: string }>('SELECT id FROM "anoauthAdmissions" WHERE space = ? AND identity = ? AND "revalidateDays" > 0', [route.admin, p.identity]))
    for (const a of mine) if (keys.has(a.id)) await this.db.execute('UPDATE "anoauthAdmissions" SET "provedAt" = ? WHERE space = ? AND id = ?', [this.#now(), route.admin, a.id])
  }

  async #putRequest(admin: string, id: string, link: string, p: RequestPayload, role: GrantRole, status: string, proof: unknown, subjectKey: string | null): Promise<void> {
    await this.db.execute(
      `INSERT INTO "anoauthRequests" (space, id, link, identity, name, devices, role, status, proof, "subjectKey") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (space, id) DO UPDATE SET link = excluded.link, name = excluded.name, devices = excluded.devices, role = excluded.role, status = excluded.status, proof = excluded.proof, "subjectKey" = excluded."subjectKey"`,
      [admin, id, link, p.identity, p.name, JSON.stringify(p.devices), role, status, proof === null ? null : JSON.stringify(proof), subjectKey],
    )
  }

  async #findRequest(id: string) {
    for (const g of await this.#guards()) {
      const r = (await this.#rows<{ link: string; identity: string; devices: string; role: string; status: string; proof: string | null; subjectKey: string | null }>(
        'SELECT link, identity, devices, role, status, proof, "subjectKey" FROM "anoauthRequests" WHERE space = ? AND id = ?',
        [g.admin, id],
      ))[0]
      if (r) return { g, r }
    }
    return null
  }

  async #requireAdmin(space: string): Promise<string> {
    if (!MANAGERS.has(this.db.roleIn(space))) throw new Error('anoAuth: only owners and admins can do this')
    const admin = await this.adminSpaceOf(space)
    if (!admin) throw new Error('anoAuth: anoAuth is not enabled for this space (auth.enable(space) by the owner)')
    return admin
  }

  #ownerOf(space: string): string | undefined {
    return this.db.members(space).find((m) => m.role === 'owner')?.identity
  }

  #rows<R>(sql: string, params: readonly unknown[] = []): Promise<R[]> {
    return this.db.execute<R>(sql, params)
  }
}

export async function createAnoAuth(db: DB, opts: AnoAuthOptions = {}): Promise<AnoAuth> {
  const a = new AnoAuth(db, opts)
  await a.start()
  return a
}

import { generateSecretKey } from 'nostr-tools/pure'
import { describe, expect, it } from 'vitest'
import { issueCertificate, issuerPubkey } from '../src/index.js'
import { relay, sleep, until, user } from './helpers/setup.js'

const issuerSk = generateSecretKey()
const issuer = issuerPubkey(issuerSk)
const cert = (subject: string, email: string, extra: Record<string, string> = {}) => ({ type: 'certificate', data: issueCertificate(issuerSk, { subject, claims: { email, ...extra } }) })
const isMember = (u: { db: { members(s: string): Array<{ identity: string }> } }, space: string, who: string) => u.db.members(space).some((m) => m.identity === who)

async function guarded() {
  const r = await relay()
  const owner = await user(r)
  const space = await owner.db.createSpace('Team')
  await owner.auth.enable(space)
  await owner.db.insertInto('notes').values({ text: 'team note', space }).execute()
  return { r, owner, space }
}

describe('anoAuth', () => {
  it('admits by a signed certificate that matches a rule, and the invitation is accepted automatically', async () => {
    const { r, owner, space } = await guarded()
    await owner.auth.setRules(space, [{ proof: { type: 'certificate', issuer }, emailDomain: 'company.com', role: 'writer' }])
    const link = await owner.auth.createLink(space)
    expect(owner.auth.parseLink(link)).toMatchObject({ space, accepts: ['certificate'] })

    const alice = await user(r)
    await alice.auth.requestJoin(link, { name: 'Alice', proofs: [cert(alice.db.pubkey, 'alice@company.com')] })
    await until(async () => (await alice.db.selectFrom('notes').select('text').where('space', '=', space).execute()).length === 1, 6000, 'alice joins')
    expect(owner.db.members(space).find((m) => m.identity === alice.db.pubkey)?.role).toBe('writer')
    expect(await owner.auth.admissions(space)).toMatchObject([{ identity: alice.db.pubkey, proofType: 'certificate', issuer, subject: 'alice@company.com', revalidateDays: 90 }])
  })

  it('refuses proofs that do not match, are bound to another key, or come from an untrusted issuer', async () => {
    const { r, owner, space } = await guarded()
    await owner.auth.setRules(space, [{ proof: { type: 'certificate', issuer }, emailDomain: 'company.com', role: 'writer' }])
    const link = await owner.auth.createLink(space)
    const eve = await user(r)
    const mallory = await user(r)
    const victim = await user(r)
    const other = generateSecretKey()
    await eve.auth.requestJoin(link, { proofs: [cert(eve.db.pubkey, 'eve@gmail.com')] })
    await mallory.auth.requestJoin(link, { proofs: [cert(victim.db.pubkey, 'victim@company.com')] }) // stolen: names another key
    await victim.auth.requestJoin(link, { proofs: [{ type: 'certificate', data: issueCertificate(other, { subject: victim.db.pubkey, claims: { email: 'victim@company.com' } }) }] })
    await sleep(1200)
    for (const u of [eve, mallory, victim]) expect(isMember(owner, space, u.db.pubkey)).toBe(false)
  })

  it('approval rule: the request waits for an admin', async () => {
    const { r, owner, space } = await guarded()
    await owner.auth.setRules(space, [{ proof: 'approval', role: 'reader' }])
    const link = await owner.auth.createLink(space, { singleUse: true })
    const bob = await user(r)
    await bob.auth.requestJoin(link, { name: 'Bob' })
    await until(async () => (await owner.auth.requests(space)).length === 1, 4000, 'request')
    const [req] = await owner.auth.requests(space)
    expect(req).toMatchObject({ identity: bob.db.pubkey, name: 'Bob', role: 'reader', status: 'pending' })
    expect(isMember(owner, space, bob.db.pubkey)).toBe(false)
    await owner.auth.approve(req!.id)
    await until(() => bob.db.spaces().some((s) => s.id === space && s.status === 'active'), 6000, 'bob joins')
    expect(await owner.auth.requests(space)).toEqual([])
    expect((await owner.auth.links(space))[0]?.usedBy).toBe(bob.db.pubkey)
  })

  it('one person = one key: a second key for the same email waits for an admin to replace the old one', async () => {
    const { r, owner, space } = await guarded()
    await owner.auth.setRules(space, [{ proof: { type: 'certificate', issuer }, email: ['alice@company.com'], role: 'writer' }])
    const link = await owner.auth.createLink(space)
    const alice = await user(r)
    await alice.auth.requestJoin(link, { proofs: [cert(alice.db.pubkey, 'alice@company.com')] })
    await until(() => isMember(owner, space, alice.db.pubkey), 6000, 'alice admitted')
    const alice2 = await user(r)
    await alice2.auth.requestJoin(link, { proofs: [cert(alice2.db.pubkey, 'alice@company.com')] })
    await until(async () => (await owner.auth.requests(space)).some((q) => q.status === 'conflict'), 4000, 'conflict')
    expect(isMember(owner, space, alice2.db.pubkey)).toBe(false)
    await owner.auth.approve((await owner.auth.requests(space))[0]!.id)
    expect(isMember(owner, space, alice.db.pubkey)).toBe(false)
    expect(isMember(owner, space, alice2.db.pubkey)).toBe(true)
  })

  it('rules, links and requests are hidden from regular members; only the owner may grant admin', async () => {
    const { r, owner, space } = await guarded()
    await owner.auth.setRules(space, [{ proof: 'link', role: 'writer' }])
    const link = await owner.auth.createLink(space)
    const carol = await user(r)
    await carol.auth.requestJoin(link)
    await until(() => carol.db.spaces().some((s) => s.id === space && s.status === 'active'), 6000, 'carol joins')
    expect(await carol.auth.adminSpaceOf(space)).toBeNull()
    expect(await carol.db.execute('SELECT * FROM "anoauthRules"')).toEqual([])
    await expect(carol.auth.setRules(space, [{ proof: 'link', role: 'writer' }])).rejects.toThrow(/owners and admins/)

    // Promote carol: the owner's device adds her to the admin space, and she can now manage links
    await owner.db.setRole(space, carol.db.pubkey, 'admin')
    await until(async () => (await carol.auth.adminSpaceOf(space)) !== null, 6000, 'carol in admin space')
    await until(async () => (await carol.auth.rules(space)).length === 1, 4000, 'rules visible')
    await expect(carol.auth.setRules(space, [{ proof: 'link', role: 'admin' }])).rejects.toThrow(/only the owner/)
    await expect(carol.auth.createLink(space)).resolves.toMatch(/^anoauth:\/\/join/)
    // Writing an admin-granting rule directly does not help: it is ignored unless the owner wrote it
    const admin = (await carol.auth.adminSpaceOf(space))!
    await carol.db.execute('INSERT INTO "anoauthRules" (space, id, position, rule) VALUES (?, ?, ?, ?)', [admin, 'sneaky', -1, JSON.stringify({ proof: 'link', role: 'admin' })])
    await until(async () => (await owner.auth.rules(space)).some((x) => x.id === 'sneaky'), 4000, 'rule synced')
    expect((await owner.auth.rules(space)).find((x) => x.id === 'sneaky')?.active).toBe(false)
  })

  it('members admitted by a proof must renew it; overdue members are removed', async () => {
    let t = Date.now()
    const r = await relay()
    const owner = await user(r, { now: () => t })
    const space = await owner.db.createSpace('Team')
    await owner.auth.enable(space)
    await owner.auth.setRules(space, [{ proof: { type: 'certificate', issuer }, emailDomain: 'company.com', role: 'writer', revalidateDays: 30 }])
    const link = await owner.auth.createLink(space)
    const alice = await user(r)
    const dave = await user(r)
    await alice.auth.requestJoin(link, { proofs: [cert(alice.db.pubkey, 'alice@company.com')] })
    await dave.auth.requestJoin(link, { proofs: [cert(dave.db.pubkey, 'dave@company.com')] })
    await until(() => isMember(owner, space, alice.db.pubkey) && isMember(owner, space, dave.db.pubkey), 6000, 'both admitted')
    await until(async () => (await alice.db.execute('SELECT id FROM "anoauthChannel" WHERE space = ?', [space])).length === 1, 6000, 'alice synced')
    t += 20 * 86_400_000
    await alice.auth.renew(space, [cert(alice.db.pubkey, 'alice@company.com')])
    await until(async () => (await owner.auth.admissions(space)).find((a) => a.identity === alice.db.pubkey)!.provedAt === t, 4000, 'renewed')
    t += 15 * 86_400_000
    expect(await owner.auth.sweep()).toBe(1)
    expect(isMember(owner, space, dave.db.pubkey)).toBe(false)
    expect(isMember(owner, space, alice.db.pubkey)).toBe(true)
  })

  it('revoked and expired links are ignored', async () => {
    const { r, owner, space } = await guarded()
    await owner.auth.setRules(space, [{ proof: 'link', role: 'reader' }])
    const revoked = await owner.auth.createLink(space)
    await owner.auth.revokeLink(space, revoked)
    const expired = await owner.auth.createLink(space, { expiresInMs: -1 })
    const x = await user(r)
    const y = await user(r)
    await x.auth.requestJoin(revoked)
    await y.auth.requestJoin(expired)
    await sleep(1000)
    expect(isMember(owner, space, x.db.pubkey) || isMember(owner, space, y.db.pubkey)).toBe(false)
  })
})

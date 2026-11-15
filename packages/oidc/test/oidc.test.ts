import { describe, expect, it } from 'vitest'
import { proofNonce } from '@anoauth/core'
import { GOOGLE, oidcProof, oidcVerifier } from '../src/index.js'
import { relay, sleep, until, user } from '../../core/test/helpers/setup.js'

const CLIENT = 'my-app.apps.googleusercontent.com'
const b64url = (b: Uint8Array | string) => Buffer.from(typeof b === 'string' ? new TextEncoder().encode(b) : b).toString('base64url')

async function fakeGoogle() {
  const kp = (await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify'])) as CryptoKeyPair
  const jwk = { ...(await crypto.subtle.exportKey('jwk', kp.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' }
  const fetch = (async (url: string) => {
    if (url === `${GOOGLE}/.well-known/openid-configuration`) return new Response(JSON.stringify({ jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs' }))
    if (url === 'https://www.googleapis.com/oauth2/v3/certs') return new Response(JSON.stringify({ keys: [jwk] }))
    return new Response('not found', { status: 404 })
  }) as typeof globalThis.fetch
  const token = async (claims: Record<string, unknown>) => {
    const now = Math.floor(Date.now() / 1000)
    const h = b64url(JSON.stringify({ alg: 'RS256', kid: 'k1', typ: 'JWT' }))
    const b = b64url(JSON.stringify({ iss: GOOGLE, aud: CLIENT, sub: '1234', email_verified: true, iat: now, exp: now + 3600, ...claims }))
    const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', kp.privateKey, new TextEncoder().encode(`${h}.${b}`)))
    return `${h}.${b}.${b64url(sig)}`
  }
  return { fetch, token }
}

describe('@anoauth/oidc', () => {
  it('verifies signature, audience, nonce and age', async () => {
    const g = await fakeGoogle()
    const v = oidcVerifier({ providers: [{ issuer: GOOGLE, clientId: CLIENT }], fetch: g.fetch })
    const ctx = { identity: 'a'.repeat(64), secret: 'b'.repeat(32), now: Date.now() }
    const nonce = proofNonce(ctx.identity, ctx.secret)
    expect(await v.verify({ idToken: await g.token({ nonce, email: 'Alice@Company.com' }) }, ctx)).toMatchObject({ type: 'oidc', issuer: GOOGLE, subject: 'alice@company.com' })
    expect(await v.verify({ idToken: await g.token({ nonce, aud: 'another-app' }) }, ctx)).toBeNull()
    expect(await v.verify({ idToken: await g.token({ nonce: proofNonce('c'.repeat(64), ctx.secret) }) }, ctx)).toBeNull()
    expect(await v.verify({ idToken: await g.token({ nonce, iat: Math.floor(Date.now() / 1000) - 8 * 86_400 }) }, ctx)).toBeNull()
    const forged = (await g.token({ nonce, email: 'alice@company.com' })).split('.')
    forged[1] = b64url(JSON.stringify({ iss: GOOGLE, aud: CLIENT, sub: '1', email: 'boss@company.com', email_verified: true, iat: Math.floor(Date.now() / 1000), nonce }))
    expect(await v.verify({ idToken: forged.join('.') }, ctx)).toBeNull()
    // a token older than its 1-hour exp is still fine within 7 days (admins may come online later)
    expect(await v.verify({ idToken: await g.token({ nonce, iat: Math.floor(Date.now() / 1000) - 2 * 86_400 }) }, ctx)).not.toBeNull()
  })

  it('end to end: "anyone who signs in with Google as @company.com joins as writer"', async () => {
    const g = await fakeGoogle()
    const r = await relay()
    const verifiers = [oidcVerifier({ providers: [{ issuer: GOOGLE, clientId: CLIENT }], fetch: g.fetch })]
    const owner = await user(r, { verifiers })
    const space = await owner.db.createSpace('Team')
    await owner.auth.enable(space)
    await owner.auth.setRules(space, [{ proof: { type: 'oidc', issuer: GOOGLE }, emailDomain: 'company.com', role: 'writer' }])
    const link = await owner.auth.createLink(space)
    expect(owner.auth.parseLink(link)?.accepts).toEqual(['oidc'])

    const alice = await user(r)
    const eve = await user(r)
    await alice.auth.requestJoin(link, { proofs: [oidcProof(await g.token({ nonce: await alice.auth.nonceFor(link), email: 'alice@company.com' }))] })
    // eve replays alice's kind of token with her own key but a nonce for alice: refused
    await eve.auth.requestJoin(link, { proofs: [oidcProof(await g.token({ nonce: await alice.auth.nonceFor(link), email: 'eve@company.com' }))] })
    await until(() => alice.db.spaces().some((s) => s.id === space && s.status === 'active'), 6000, 'alice joins')
    await sleep(300)
    expect(owner.db.members(space).map((m) => m.identity).sort()).toEqual([owner.db.pubkey, alice.db.pubkey].sort())
    expect((await owner.auth.admissions(space))[0]).toMatchObject({ proofType: 'oidc', issuer: GOOGLE, subject: 'alice@company.com' })
  })
})

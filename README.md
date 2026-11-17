# anoAuth

**Who may join** a shared [anoDB](https://github.com/sho-ritz/anodb) space — invite links, admin approval,
certificates from an issuer you trust, and sign-in with Google / Microsoft / your company's SSO.

anoDB only knows public keys: it adds members (`addMember(space, npub, role, { devices })`), removes
them and delivers the encryption keys. anoAuth runs on the owner's and admins' devices, decides whether
a request qualifies, and calls `addMember`. No server is required.

> **Status: v0.1 / experimental.** Packages: `@anoauth/core`, `@anoauth/oidc`, `@anoauth/react`, `@anoauth/cli`. Design decisions: [docs/DECISIONS.md](docs/DECISIONS.md).

## Setup

```ts
import { createAnoDB, defineSchema } from '@anodb/core'
import { anoauthTables, createAnoAuth } from '@anoauth/core'

const schema = defineSchema({ ...yourTables, ...anoauthTables })
const db = await createAnoDB({ appId, schema, driver })
const auth = await createAnoAuth(db)
```

## Owner / admins

```ts
const team = await db.createSpace('Team')
await auth.enable(team)                          // owner, once: creates the admin space

await auth.setRules(team, [
  { proof: { type: 'certificate', issuer: 'npub1issuer…' }, emailDomain: 'company.com', role: 'writer' },
  { proof: { type: 'certificate', issuer: 'npub1issuer…' }, email: ['boss@company.com'], role: 'admin' }, // reservation
  { proof: 'approval', role: 'reader' },         // everyone else: an admin approves by hand
])
const link = await auth.createLink(team)         // reusable, 30 days; { singleUse: true }, { expiresInMs: null }

await auth.requests(team)                        // waiting for approval, or "same person, new key"
await auth.approve(id); await auth.reject(id)
await auth.revokeLink(team, link)
await auth.admissions(team)                      // who joined, how, and when they last proved it
```

- Rules are evaluated in order; the first match decides. `proof: 'link'` admits anyone with the link.
- Requests are handled automatically by any owner / admin device that is online. Until one is, the
  applicant waits — or run the **gatekeeper** (below).
- Rules, links, requests and admission records live in a separate **admin space** (the space's owner
  and admins only). Regular members can't read or change them.
- Only the owner can create rules that grant `admin`, and only the owner's device admits admins.
- **One person = one key**: a second key proving the same email is not admitted automatically; an
  admin's `approve` replaces the old key.
- Members admitted by a proof re-prove every 90 days (`revalidateDays`); overdue members are removed.

## Applicants

```ts
const info = auth.parseLink(link)                // { space, accepts: ['certificate'] }
await auth.requestJoin(link, { name: 'Alice', proofs: [{ type: 'certificate', data: certificate }] })
// When an admin device admits you, the invitation is accepted automatically.

await auth.renew(team, [{ type: 'certificate', data: freshCertificate }])   // before 90 days pass
```

## Certificates

A certificate is a signed Nostr event: "the issuer vouches that pubkey P has these attributes".
Anyone with a key can be an issuer — a company's backend, a script, a future anoAuth issuer.

```ts
import { issueCertificate } from '@anoauth/core'
const certificate = issueCertificate(issuerSecretKey, {
  subject: alicePubkeyHex,                      // bound to her key: useless for anyone else
  claims: { email: 'alice@company.com', department: 'sales' },
  expiresAt: Date.now() + 7 * 86_400_000,
})
```

## Sign in with Google / Microsoft / SSO (`@anoauth/oidc`)

```ts
import { GOOGLE, handleOidcRedirect, oidcProofSource, oidcVerifier } from '@anoauth/oidc'

if (handleOidcRedirect()) { /* this is the sign-in popup: stop here */ }
const auth = await createAnoAuth(db, { verifiers: [oidcVerifier({ providers: [{ issuer: GOOGLE, clientId }] })] })
await auth.setRules(team, [{ proof: { type: 'oidc', issuer: GOOGLE }, emailDomain: 'company.com', role: 'writer' }])
```

Register an OAuth client at the provider with your app's URL as JavaScript origin and redirect URI.
The token is requested in the browser with a nonce bound to the applicant's key and the link, so a
leaked token is useless to anyone else; admins check the provider's signature, issuer and audience.

## React (`@anoauth/react`)

```tsx
<AnoAuthProvider auth={auth}>
  <InviteLinks space={id} />     {/* owners / admins: create, QR, copy, revoke */}
  <JoinRequests space={id} />    {/* approve / reject */}
  <RulesEditor space={id} />     {/* who may join */}
  <JoinWithLink proofs={[oidcProofSource({ issuer: GOOGLE, clientId, label: 'Continue with Google' })]} onJoined={open} />
</AnoAuthProvider>
```

Used by [anoTalk](https://github.com/sho-ritz/anotalk).

## Gatekeeper (`@anoauth/cli`)

An always-on admin device that admits qualifying requests while your admins are offline:

```sh
npx @anoauth/cli gatekeeper --app com.example.app --trust npub1owner… [--google-client-id …]
# from the owner's app, once: db.addMember(space, '<gatekeeper npub>', 'admin')
```

It joins only spaces offered by the owners you trust, keeps its keys in a mode-600 file, and can
read the spaces it guards (it is an admin): run it on a machine you trust.

## Custom proof types and decisions

```ts
createAnoAuth(db, {
  verifiers: [myVerifier],                      // { type, verify(data, { identity, secret, now }) }
  check: async (req) => (req.proofs[0]?.claims.department === 'sales' ? 'writer' : undefined),
})
```

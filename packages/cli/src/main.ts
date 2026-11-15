#!/usr/bin/env node
import { homedir } from 'node:os'
import { join } from 'node:path'
import { parseArgs } from 'node:util'
import { anoauthTables, createAnoAuth, isAdminSpace } from '@anoauth/core'
import { GOOGLE, oidcVerifier } from '@anoauth/oidc'
import { DEFAULT_RELAYS, createAnoDB, defineSchema } from '@anodb/core'
import { nodeSqlite } from '@anodb/core/node'
import * as nip19 from 'nostr-tools/nip19'
import { fileKeyStore } from './keystore.js'

const HELP = `anoauth gatekeeper — an always-on admin device for anoAuth

Usage:
  npx @anoauth/cli gatekeeper --app <appId> --trust <owner npub> [options]

It admits join requests that match a space's rules while your admins are offline.
Make it an admin of a space from the owner's app:  db.addMember(space, '<gatekeeper npub>', 'admin')

Options:
  --app <appId>            appId of your app (required)
  --trust <npub>           accept spaces only from these owners (repeatable, required)
  --dir <path>             data directory (default ~/.config/anoauth/<appId>)
  --relays <a,b,…>         relays (default: anoDB's defaults)
  --google-client-id <id>  verify "Sign in with Google" proofs for this OAuth client id
  --oidc <issuer>=<id>     verify another OIDC provider (repeatable)

Security: the gatekeeper is an admin, so it can read the spaces it guards. Run it on a machine you trust.
Its keys are in <dir>/keys.json (mode 600).
`

async function main() {
  const [cmd, ...rest] = process.argv.slice(2)
  if (cmd !== 'gatekeeper') {
    process.stdout.write(HELP)
    process.exit(cmd === undefined || cmd === '--help' || cmd === '-h' ? 0 : 1)
  }
  const { values } = parseArgs({
    args: rest,
    options: {
      app: { type: 'string' },
      trust: { type: 'string', multiple: true },
      dir: { type: 'string' },
      relays: { type: 'string' },
      'google-client-id': { type: 'string' },
      oidc: { type: 'string', multiple: true },
    },
  })
  if (!values.app || !values.trust?.length) {
    process.stderr.write(HELP)
    process.exit(1)
  }
  const trusted = new Set(
    values.trust.map((t) => {
      const d = nip19.decode(t)
      if (d.type !== 'npub') throw new Error(`--trust expects an npub: ${t}`)
      return d.data
    }),
  )
  const dir = values.dir ?? join(homedir(), '.config', 'anoauth', values.app)
  const relays = values.relays ? values.relays.split(',').map((r) => r.trim()) : DEFAULT_RELAYS
  const providers = [
    ...(values['google-client-id'] ? [{ issuer: GOOGLE, clientId: values['google-client-id'] }] : []),
    ...(values.oidc ?? []).map((o) => {
      const i = o.lastIndexOf('=')
      return { issuer: o.slice(0, i), clientId: o.slice(i + 1) }
    }),
  ]

  const log = (...a: unknown[]) => console.log(new Date().toISOString().slice(0, 19).replace('T', ' '), ...a)
  // The gatekeeper only needs anoAuth's tables; the app's own tables stay unprojected.
  const db = await createAnoDB({
    appId: values.app,
    schema: defineSchema({ ...anoauthTables }),
    driver: nodeSqlite(join(dir, 'db.sqlite')),
    keyStore: fileKeyStore(join(dir, 'keys.json')),
    relays,
    deviceName: 'anoAuth gatekeeper',
  })
  await db.publishKeyPackage().catch((e: Error) => log('could not publish the key package:', e.message))

  const accept = async (i: { space: string; name: string; from: string }) => {
    if (isAdminSpace(i)) return // handled by anoAuth (only from the guarded space's owner)
    if (!trusted.has(i.from)) return log(`ignored an invitation to "${i.name}" from an untrusted ${nip19.npubEncode(i.from)}`)
    await db.acceptInvitation(i.space)
    log(`joined "${i.name}" (${i.space})`)
  }
  db.onInvitation((i) => void accept(i).catch((e: Error) => log('error:', e.message)))
  for (const i of db.invitations()) await accept(i)

  const auth = await createAnoAuth(db, { relays, verifiers: providers.length ? [oidcVerifier({ providers })] : [], sweepIntervalMs: 15 * 60_000 })
  log(`anoAuth gatekeeper for app "${values.app}"`)
  log(`npub: ${db.npub}`)
  log(`make it an admin from the owner's app: db.addMember(space, '${db.npub}', 'admin')`)
  log(`relays: ${relays.join(', ')}${providers.length ? ` · OIDC: ${providers.map((p) => p.issuer).join(', ')}` : ''}`)

  let last = ''
  const report = async () => {
    const lines: string[] = []
    for (const s of db.spaces().filter((x) => x.status === 'active' && !x.personal && !isAdminSpace(x))) {
      const guarded = (await auth.adminSpaceOf(s.id)) !== null
      const pending = guarded ? (await auth.requests(s.id)).length : 0
      lines.push(`"${s.name}": ${db.members(s.id).length} members, ${guarded ? `guarding, ${pending} waiting for a human` : 'not guarded yet (the owner app must be online once)'}`)
    }
    const text = lines.join('\n')
    if (text !== last) {
      last = text
      if (text) log(`status\n  ${lines.join('\n  ')}`)
    }
  }
  db.onChange(() => void report().catch(() => {}))
  setInterval(() => void report().catch(() => {}), 30_000)
  await report()

  const stop = async () => {
    log('stopping')
    auth.close()
    await db.close()
    process.exit(0)
  }
  process.on('SIGINT', () => void stop())
  process.on('SIGTERM', () => void stop())
}

main().catch((e: Error) => {
  console.error(`anoauth: ${e.message}`)
  process.exit(1)
})

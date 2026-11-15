import { type ChildProcess, spawn } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'
import { relay, until, user } from '../../core/test/helpers/setup.js'

const main = fileURLToPath(new URL('../dist/main.js', import.meta.url))
const procs: ChildProcess[] = []
afterEach(() => {
  for (const p of procs.splice(0)) p.kill('SIGTERM')
})

function gatekeeper(args: string[]): Promise<{ npub: string; out: () => string }> {
  const p = spawn(process.execPath, [main, 'gatekeeper', ...args], { stdio: ['ignore', 'pipe', 'pipe'] })
  procs.push(p)
  let out = ''
  p.stdout.on('data', (d) => (out += d))
  p.stderr.on('data', (d) => (out += d))
  return new Promise((resolve, reject) => {
    const t = setInterval(() => {
      const m = /npub: (npub1[0-9a-z]+)/.exec(out)
      if (m) {
        clearInterval(t)
        resolve({ npub: m[1]!, out: () => out })
      }
    }, 50)
    p.on('exit', (c) => reject(new Error(`gatekeeper exited ${c}: ${out}`)))
  })
}

describe('anoauth gatekeeper', () => {
  it('admits a qualifying request while the owner is offline', async () => {
    const r = await relay()
    const owner = await user(r)
    const gk = await gatekeeper(['--app', 'test', '--trust', owner.db.npub, '--relays', r.url, '--dir', mkdtempSync(join(tmpdir(), 'anoauth-gk-'))])
    const space = await owner.db.createSpace('Team')
    await owner.auth.enable(space)
    await owner.auth.setRules(space, [{ proof: 'link', role: 'writer' }])
    const link = await owner.auth.createLink(space)
    await until(async () => {
      try {
        await owner.db.addMember(space, gk.npub, 'admin')
        return true
      } catch {
        return false // key package not on the relay yet
      }
    }, 8000, 'gatekeeper key package')
    await until(() => gk.out().includes('guarding'), 15000, `gatekeeper guarding\n${gk.out()}`)

    // The owner goes offline; a newcomer asks to join
    owner.auth.close()
    await owner.db.close()
    const alice = await user(r)
    await alice.auth.requestJoin(link, { name: 'Alice' })
    await until(() => alice.db.spaces().some((s) => s.id === space && s.status === 'active'), 15000, `alice admitted by the gatekeeper\n${gk.out()}`)
    expect(alice.db.members(space).map((m) => m.role).sort()).toEqual(['admin', 'owner', 'writer'])
  }, 40_000)

  it('ignores spaces offered by owners it does not trust', async () => {
    const r = await relay()
    const owner = await user(r)
    const stranger = await user(r)
    const gk = await gatekeeper(['--app', 'test', '--trust', owner.db.npub, '--relays', r.url, '--dir', mkdtempSync(join(tmpdir(), 'anoauth-gk-'))])
    const space = await stranger.db.createSpace('Spam')
    await until(async () => {
      try {
        await stranger.db.addMember(space, gk.npub, 'admin')
        return true
      } catch {
        return false
      }
    }, 8000, 'key package')
    await until(() => gk.out().includes('untrusted'), 8000, 'ignored')
  }, 20_000)
})

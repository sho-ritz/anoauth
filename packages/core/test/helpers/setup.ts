import { afterEach } from 'vitest'
import { type AnoDBOptions, createAnoDB, defineSchema, memoryKeyStore } from '@anodb/core'
import { nodeSqlite } from '@anodb/core/node'
import { type AnoAuthOptions, anoauthTables, createAnoAuth } from '../../src/index.js'
import { MockRelay } from './mock-relay.js'

const cleanup: Array<() => unknown> = []
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) await fn()
})

export const schema = defineSchema({ notes: { text: 'text' }, ...anoauthTables })

export async function relay(): Promise<MockRelay> {
  const r = await new MockRelay().start()
  cleanup.push(() => r.stop())
  return r
}

const relayOptions = { reconnectMinMs: 30, reconnectMaxMs: 100, publishTimeoutMs: 500 }

/** An anoDB user with anoAuth attached. */
export async function user(r: MockRelay, opts: AnoAuthOptions = {}, extra: Partial<AnoDBOptions<typeof schema>> = {}) {
  const db = await createAnoDB({ appId: 'test', schema, driver: nodeSqlite(':memory:'), keyStore: memoryKeyStore(), relays: [r.url], relayOptions, retryIntervalMs: 100, ...extra })
  const auth = await createAnoAuth(db, { relays: [r.url], relayOptions, sweepIntervalMs: 3600_000, ...opts })
  cleanup.push(() => db.close())
  cleanup.push(() => auth.close())
  return { db, auth }
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

export async function until(cond: () => boolean | Promise<boolean>, timeoutMs = 4000, what = 'condition'): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!(await cond())) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`)
    await sleep(25)
  }
}

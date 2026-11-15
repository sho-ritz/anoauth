import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import type { KeyName, KeyStore } from '@anodb/core'

const enc = new TextEncoder()

/**
 * Keys in a JSON file readable only by this user (0600, directory 0700). Group keys stored in
 * SQLite are sealed with AES-GCM under a key derived from the device key, so the database file
 * alone reveals nothing.
 */
export function fileKeyStore(path: string): KeyStore {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  const load = (): Partial<Record<KeyName, string>> => {
    if (!existsSync(path)) return {}
    if ((statSync(path).mode & 0o077) !== 0) throw new Error(`anoauth: ${path} is readable by others; run chmod 600 ${path}`)
    return JSON.parse(readFileSync(path, 'utf8')) as Partial<Record<KeyName, string>>
  }
  const save = (v: Partial<Record<KeyName, string>>) => {
    writeFileSync(path, JSON.stringify(v, null, 2), { mode: 0o600 })
    chmodSync(path, 0o600)
  }
  let sealKey: Promise<CryptoKey> | null = null
  const key = () =>
    (sealKey ??= (async () => {
      const device = load().device
      if (!device) throw new Error('anoauth: no device key yet')
      const raw = await crypto.subtle.digest('SHA-256', enc.encode(`anoauth/gatekeeper/seal/${device}`))
      return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt'])
    })())
  return {
    kind: 'file',
    get: async (n) => load()[n] ?? null,
    set: async (n, v) => save({ ...load(), [n]: v }),
    remove: async (n) => {
      const v = load()
      delete v[n]
      save(v)
    },
    seal: async (p) => {
      const iv = crypto.getRandomValues(new Uint8Array(12))
      const c = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await key(), new Uint8Array(p)))
      return new Uint8Array([...iv, ...c])
    },
    open: async (s) => new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(s.slice(0, 12)) }, await key(), new Uint8Array(s.slice(12)))),
  }
}

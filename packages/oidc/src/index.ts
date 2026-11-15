import { type ProofEnvelope, type Verified, type Verifier, proofNonce } from '@anoauth/core'

/**
 * OpenID Connect for anoAuth: applicants sign in with Google / Microsoft / a company SSO in the
 * browser (no server: the provider hands the ID token straight to the page), and owner / admin
 * devices verify the token with the provider's public keys.
 *
 * The token's `nonce` binds it to the applicant's anoDB key and to one invite link, so a leaked
 * token cannot be used by anyone else.
 */

export const GOOGLE = 'https://accounts.google.com'
/** Microsoft Entra ID for one tenant (use the tenant id; `common` issues per-tenant issuers). */
export const microsoft = (tenantId: string) => `https://login.microsoftonline.com/${tenantId}/v2.0`

export interface OidcProvider {
  /** Issuer URL (`iss`), e.g. GOOGLE. */
  issuer: string
  /** Your app's OAuth client id(s) at that provider; tokens for other apps are refused (`aud`). */
  clientId: string | string[]
  /** Override the discovery document's `jwks_uri`. */
  jwksUri?: string
}

export interface OidcVerifierOptions {
  providers: OidcProvider[]
  /** Accept tokens issued within this many days (the 1-hour `exp` is ignored, see DECISIONS 6). Default 7. */
  maxAgeDays?: number
  fetch?: typeof fetch
}

const b64urlToBytes = (s: string) => {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '='))
  return Uint8Array.from(b, (c) => c.charCodeAt(0))
}
const b64urlJson = <T>(s: string): T => JSON.parse(new TextDecoder().decode(b64urlToBytes(s))) as T
const trimSlash = (s: string) => s.replace(/\/+$/, '')

interface Jwk extends JsonWebKey {
  kid?: string
}

/** Verifies OIDC ID tokens (`{ type: 'oidc', data: { idToken } }`) on owner / admin devices. */
export function oidcVerifier(opts: OidcVerifierOptions): Verifier {
  const f = opts.fetch ?? globalThis.fetch.bind(globalThis)
  const maxAge = (opts.maxAgeDays ?? 7) * 86_400_000
  const jwksCache = new Map<string, { at: number; keys: Jwk[] }>()

  const jwks = async (p: OidcProvider, refresh: boolean): Promise<Jwk[]> => {
    const iss = trimSlash(p.issuer)
    const cached = jwksCache.get(iss)
    if (cached && !refresh && Date.now() - cached.at < 3600_000) return cached.keys
    let uri = p.jwksUri
    if (!uri) {
      const conf = (await (await f(`${iss}/.well-known/openid-configuration`)).json()) as { jwks_uri?: string }
      uri = conf.jwks_uri
    }
    if (!uri) throw new Error('no jwks_uri')
    const keys = ((await (await f(uri)).json()) as { keys?: Jwk[] }).keys ?? []
    jwksCache.set(iss, { at: Date.now(), keys })
    return keys
  }

  return {
    type: 'oidc',
    async verify(data, ctx): Promise<Verified | null> {
      const token = (data as { idToken?: unknown })?.idToken
      if (typeof token !== 'string' || token.length > 16_000) return null
      const parts = token.split('.')
      if (parts.length !== 3) return null
      const [h, b, sig] = parts as [string, string, string]
      const header = b64urlJson<{ alg?: string; kid?: string }>(h)
      const claims = b64urlJson<Record<string, unknown>>(b)
      const iss = typeof claims.iss === 'string' ? trimSlash(claims.iss) : ''
      // Google also issues "accounts.google.com" without the scheme.
      const provider = opts.providers.find((p) => trimSlash(p.issuer) === iss || (trimSlash(p.issuer) === GOOGLE && iss === 'accounts.google.com'))
      if (!provider) return null
      const auds = Array.isArray(claims.aud) ? claims.aud : [claims.aud]
      const clientIds = Array.isArray(provider.clientId) ? provider.clientId : [provider.clientId]
      if (!auds.some((a) => typeof a === 'string' && clientIds.includes(a))) return null
      if (auds.length > 1 && typeof claims.azp === 'string' && !clientIds.includes(claims.azp)) return null
      if (claims.nonce !== proofNonce(ctx.identity, ctx.secret)) return null // bound to this key + link
      const iat = typeof claims.iat === 'number' ? claims.iat * 1000 : Number.NaN
      if (!(iat >= ctx.now - maxAge && iat <= ctx.now + 5 * 60_000)) return null
      if (typeof claims.sub !== 'string') return null

      const algs: Record<string, { imp: RsaHashedImportParams | EcKeyImportParams; ver: AlgorithmIdentifier | EcdsaParams }> = {
        RS256: { imp: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, ver: { name: 'RSASSA-PKCS1-v1_5' } },
        ES256: { imp: { name: 'ECDSA', namedCurve: 'P-256' }, ver: { name: 'ECDSA', hash: 'SHA-256' } },
      }
      const alg = header.alg ? algs[header.alg] : undefined
      if (!alg) return null
      const signed = new TextEncoder().encode(`${h}.${b}`)
      const check = async (keys: Jwk[]) => {
        for (const k of keys) {
          if (header.kid && k.kid !== header.kid) continue
          try {
            const key = await crypto.subtle.importKey('jwk', k, alg.imp, false, ['verify'])
            if (await crypto.subtle.verify(alg.ver, key, b64urlToBytes(sig), signed)) return true
          } catch {}
        }
        return false
      }
      if (!(await check(await jwks(provider, false))) && !(await check(await jwks(provider, true)))) return null

      const email = typeof claims.email === 'string' && claims.email_verified !== false ? claims.email.toLowerCase() : undefined
      const kept: Record<string, unknown> = {}
      for (const k of ['sub', 'email', 'email_verified', 'name', 'hd', 'tid', 'groups', 'roles']) if (claims[k] !== undefined) kept[k] = claims[k]
      return { type: 'oidc', issuer: trimSlash(provider.issuer), subject: email ?? `sub:${claims.sub}`, claims: kept, issuedAt: iat }
    },
  }
}

/** The proof to send with `auth.requestJoin` / `auth.renew`. */
export const oidcProof = (idToken: string): ProofEnvelope => ({ type: 'oidc', data: { idToken } })

// ---- browser sign-in (popup, implicit ID-token flow, no server) -------------------------------

export interface SignInOptions {
  issuer: string
  clientId: string
  /** From `auth.nonceFor(link)` (or `auth.nonceFor(space)` to renew). */
  nonce: string
  /** Must be registered at the provider. Default: this page (origin + path). */
  redirectUri?: string
  scope?: string
  loginHint?: string
  /** e.g. `'select_account'`. */
  prompt?: string
}

const MESSAGE = 'anoauth:oidc'

/**
 * Open the provider's sign-in in a popup and resolve with the ID token. Call it from a click.
 * The popup comes back to `redirectUri`; that page must call `handleOidcRedirect()` first thing
 * (before opening the database).
 */
export async function signInWithOidc(o: SignInOptions): Promise<string> {
  const iss = trimSlash(o.issuer)
  const popup = window.open('about:blank', 'anoauth-oidc', 'width=480,height=640')
  if (!popup) throw new Error('anoAuth: the sign-in popup was blocked')
  try {
    const conf = (await (await fetch(`${iss}/.well-known/openid-configuration`)).json()) as { authorization_endpoint?: string }
    if (!conf.authorization_endpoint) throw new Error('anoAuth: provider has no authorization endpoint')
    const state = crypto.randomUUID()
    const q = new URLSearchParams({
      response_type: 'id_token',
      response_mode: 'fragment',
      client_id: o.clientId,
      redirect_uri: o.redirectUri ?? `${location.origin}${location.pathname}`,
      scope: o.scope ?? 'openid email profile',
      nonce: o.nonce,
      state,
    })
    if (o.loginHint) q.set('login_hint', o.loginHint)
    if (o.prompt) q.set('prompt', o.prompt)
    popup.location.href = `${conf.authorization_endpoint}?${q.toString()}`
    return await new Promise<string>((resolve, reject) => {
      const timer = setInterval(() => {
        if (popup.closed) {
          cleanup()
          reject(new Error('anoAuth: sign-in was cancelled'))
        }
      }, 500)
      const onMessage = (e: MessageEvent<{ t?: string; state?: string; idToken?: string; error?: string }>) => {
        if (e.origin !== location.origin || e.data?.t !== MESSAGE || e.data.state !== state) return
        cleanup()
        if (e.data.idToken) resolve(e.data.idToken)
        else reject(new Error(`anoAuth: sign-in failed (${e.data.error ?? 'unknown'})`))
      }
      const cleanup = () => {
        clearInterval(timer)
        window.removeEventListener('message', onMessage)
      }
      window.addEventListener('message', onMessage)
    })
  } catch (err) {
    popup.close()
    throw err
  }
}

/**
 * In the sign-in popup: pass the result back to the opener and close. Returns true when this page
 * is that popup — then do not open the database or render the app.
 */
export function handleOidcRedirect(): boolean {
  if (typeof window === 'undefined' || !window.opener || !location.hash) return false
  const p = new URLSearchParams(location.hash.slice(1))
  const state = p.get('state')
  if (!state || (!p.has('id_token') && !p.has('error'))) return false
  ;(window.opener as Window).postMessage({ t: MESSAGE, state, idToken: p.get('id_token') ?? undefined, error: p.get('error') ?? undefined }, location.origin)
  window.close()
  return true
}

/** For `<JoinWithLink proofs={[oidcProofSource({ … })]} />` (structurally a ProofSource of @anoauth/react). */
export function oidcProofSource(o: { issuer: string; clientId: string; label: string; redirectUri?: string; prompt?: string }) {
  return {
    type: 'oidc',
    label: o.label,
    get: async (nonce: string): Promise<ProofEnvelope> =>
      oidcProof(await signInWithOidc({ issuer: o.issuer, clientId: o.clientId, nonce, ...(o.redirectUri ? { redirectUri: o.redirectUri } : {}), ...(o.prompt ? { prompt: o.prompt } : {}) })),
  }
}

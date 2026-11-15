'use client'
/**
 * React components for anoAuth. Plain HTML with `anoauth-*` class names and only layout styles.
 *
 *   <AnoAuthProvider auth={auth}>   makes `auth` available
 *   <InviteLinks space={id} />      create / copy / revoke invite links (owners and admins)
 *   <JoinRequests space={id} />     approve / reject requests waiting for an admin
 *   <RulesEditor space={id} />      who may join (owners and admins)
 *   <JoinWithLink proofs={[…]} />   the applicant's side: open or paste a link, prove, wait
 */
import { type AnoAuth, type JoinRequestInfo, type LinkInfo, type ParsedLink, type ProofEnvelope, type Rule, type StoredRule, parseLink, toAppLink } from '@anoauth/core'
import { LINK_CHANNEL } from '@anodb/core'
import { QRCode } from '@anodb/core/react'
import { type CSSProperties, type ReactNode, createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'

const Ctx = createContext<AnoAuth | null>(null)

export function AnoAuthProvider(props: { auth: AnoAuth; children: ReactNode }) {
  return <Ctx.Provider value={props.auth}>{props.children}</Ctx.Provider>
}

export function useAnoAuth(): AnoAuth {
  const a = useContext(Ctx)
  if (!a) throw new Error('anoAuth: wrap your app in <AnoAuthProvider auth={auth}>')
  return a
}

/** Re-runs an async read whenever the database changes. */
export function useAuthQuery<T>(fn: (auth: AnoAuth) => Promise<T>, deps: readonly unknown[] = []): T | undefined {
  const auth = useAnoAuth()
  const [value, setValue] = useState<T>()
  const ref = useRef(fn)
  ref.current = fn
  useEffect(() => {
    let alive = true
    const run = () => void ref.current(auth).then((v) => alive && setValue(v), () => {})
    run()
    const off = auth.db.onChange(run)
    const t = setInterval(run, 5000) // expiry and online state are not database changes
    return () => {
      alive = false
      off()
      clearInterval(t)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auth, ...deps])
  return value
}

/** An `anoauth://join` link this page was opened with (`#anoauth=…`, also forwarded from another tab). */
export function useIncomingJoinLink(): [string | null, () => void] {
  const [link, setLink] = useState<string | null>(null)
  useEffect(() => {
    const read = () => setLink(typeof location !== 'undefined' && parseLink(location.href) ? location.href : null)
    read()
    window.addEventListener('hashchange', read)
    const ch = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel(LINK_CHANNEL) : null
    if (ch)
      ch.onmessage = (e: MessageEvent<{ href?: unknown }>) => {
        if (typeof e.data?.href === 'string' && parseLink(e.data.href)) setLink(e.data.href)
      }
    return () => {
      window.removeEventListener('hashchange', read)
      ch?.close()
    }
  }, [])
  const clear = useCallback(() => {
    setLink(null)
    if (typeof location !== 'undefined' && location.hash.includes('anoauth=')) history.replaceState(null, '', `${location.pathname}${location.search}`)
  }, [])
  return [link, clear]
}

// ---- labels ------------------------------------------------------------------------------------

export type Lang = 'en' | 'ja'

const en = {
  inviteLinks: 'Invite links',
  createReusable: 'Create link (reusable, 30 days)',
  createSingle: 'Create one-time link (24 h)',
  copy: 'Copy',
  copied: 'Copied',
  revoke: 'Revoke',
  oneTime: 'one-time',
  expires: 'expires',
  noExpiry: 'no expiry',
  linkHint: 'Anyone may open the link; the rules below decide who gets in.',
  requests: 'Waiting for approval',
  none: 'None',
  approve: 'Approve',
  reject: 'Reject',
  conflict: 'already a member with another key — approving replaces the old key',
  rules: 'Who may join',
  noRules: 'No rules yet: nobody can join with a link.',
  remove: 'Remove',
  addRule: 'Add rule',
  proofLink: 'Anyone with the link',
  proofApproval: 'An admin approves each request',
  proofCertificate: 'Certificate from an issuer',
  proofOidc: 'Sign-in with a provider (OIDC)',
  issuer: 'Issuer (npub / URL)',
  anyEmail: 'any account',
  domain: 'email domain',
  emails: 'these emails',
  value: 'company.com, or a@x.com, b@x.com',
  role: 'Role',
  inactive: '(ignored: an admin rule must be written by the owner)',
  join: 'Join with an invite link',
  inviteLink: 'Invite link',
  yourName: 'Your name',
  request: 'Request to join',
  requestPlain: 'Request without proof (an admin approves)',
  waiting: 'Request sent. You join automatically as soon as an owner or admin has the app open.',
  invalidLink: 'This is not an invite link for this app.',
  joined: 'Joined',
}
const ja: typeof en = {
  inviteLinks: '招待リンク',
  createReusable: 'リンクを作成（何度でも使える・30日）',
  createSingle: '1回だけのリンクを作成（24時間）',
  copy: 'コピー',
  copied: 'コピーしました',
  revoke: '取り消す',
  oneTime: '1回限り',
  expires: '期限',
  noExpiry: '期限なし',
  linkHint: 'リンクは誰でも開けます。入れるかどうかは下の「参加の条件」で決まります。',
  requests: '承認待ち',
  none: 'なし',
  approve: '承認',
  reject: '拒否',
  conflict: '別の鍵ですでに参加しています（承認すると古い鍵と入れ替えます）',
  rules: '参加の条件',
  noRules: '条件がまだありません。リンクから参加できる人はいません。',
  remove: '削除',
  addRule: '条件を追加',
  proofLink: 'リンクを持っている人',
  proofApproval: '管理者が1件ずつ承認',
  proofCertificate: '発行者の証明書',
  proofOidc: 'ログインで確認（OIDC）',
  issuer: '発行者（npub / URL）',
  anyEmail: 'どのアカウントでも',
  domain: 'メールのドメイン',
  emails: 'このメールアドレス',
  value: 'company.com、または a@x.com, b@x.com',
  role: '役割',
  inactive: '（無効：admin を与える条件は owner が書く必要があります）',
  join: '招待リンクで参加',
  inviteLink: '招待リンク',
  yourName: 'あなたの名前',
  request: '参加をリクエスト',
  requestPlain: '証明なしで申請（管理者の承認待ち）',
  waiting: 'リクエストを送りました。owner か admin がアプリを開くと、自動で参加します。',
  invalidLink: 'このアプリ用の招待リンクではありません。',
  joined: '参加しました',
}
export type Labels = typeof en

interface Common {
  lang?: Lang
  labels?: Partial<Labels>
  className?: string
}
const useLabels = (p: Common): Labels => {
  const lang = p.lang ?? (typeof navigator !== 'undefined' && navigator.language.startsWith('ja') ? 'ja' : 'en')
  return { ...(lang === 'ja' ? ja : en), ...p.labels }
}
const col: CSSProperties = { display: 'flex', flexDirection: 'column', gap: 8 }
const row: CSSProperties = { display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }
const list: CSSProperties = { listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 8 }
const mono: CSSProperties = { fontFamily: 'ui-monospace, Menlo, monospace', fontSize: 12, wordBreak: 'break-all' }

function useRun() {
  const [error, setError] = useState<string | null>(null)
  const run = useCallback(async <T,>(p: Promise<T>): Promise<T | undefined> => {
    setError(null)
    try {
      return await p
    } catch (e) {
      setError((e as Error).message)
      return undefined
    }
  }, [])
  return { error, setError, run }
}
const ErrorText = ({ error }: { error: string | null }) =>
  error ? (
    <span className="anoauth-error" role="alert">
      {error}
    </span>
  ) : null

const MANAGERS = new Set(['owner', 'admin'])

// ---- admins ------------------------------------------------------------------------------------

export interface InviteLinksProps extends Common {
  space: string
  /** Base URL of the app for links and QR codes. Default: this page. */
  linkBase?: string
}

/** Create, copy and revoke invite links of a space (owners and admins). */
export function InviteLinks(props: InviteLinksProps) {
  const l = useLabels(props)
  const auth = useAnoAuth()
  const links = useAuthQuery((a) => a.links(props.space), [props.space])
  const { error, run } = useRun()
  const [copied, setCopied] = useState<string | null>(null)
  if (!MANAGERS.has(auth.db.roleIn(props.space) ?? '')) return null
  const now = Date.now()
  const active = (links ?? []).filter((x: LinkInfo) => !x.revoked && (x.expiresAt === null || x.expiresAt > now) && !(x.singleUse && x.usedBy))
  return (
    <section className={props.className ?? 'anoauth-links'} style={col}>
      <h3 style={{ margin: 0 }}>{l.inviteLinks}</h3>
      <div style={row}>
        <button className="anoauth-button" onClick={() => void run(auth.createLink(props.space))}>
          {l.createReusable}
        </button>
        <button className="anoauth-button anoauth-secondary" onClick={() => void run(auth.createLink(props.space, { singleUse: true, expiresInMs: 86_400_000 }))}>
          {l.createSingle}
        </button>
      </div>
      <span className="anoauth-hint">{l.linkHint}</span>
      <ul style={list}>
        {active.map((x) => {
          const url = toAppLink(x.uri, props.linkBase)
          return (
            <li key={x.id} style={col}>
              <QRCode value={url} size={160} />
              <span style={mono}>{url}</span>
              <div style={row}>
                <button
                  className="anoauth-button"
                  onClick={() =>
                    void navigator.clipboard.writeText(url).then(() => {
                      setCopied(x.id)
                      setTimeout(() => setCopied(null), 1500)
                    })
                  }
                >
                  {copied === x.id ? l.copied : l.copy}
                </button>
                <button className="anoauth-button anoauth-secondary" onClick={() => void run(auth.revokeLink(props.space, x.id))}>
                  {l.revoke}
                </button>
                <span className="anoauth-hint">
                  {x.singleUse ? `${l.oneTime} · ` : ''}
                  {x.expiresAt === null ? l.noExpiry : `${l.expires} ${new Date(x.expiresAt).toLocaleDateString()}`}
                </span>
              </div>
            </li>
          )
        })}
      </ul>
      <ErrorText error={error} />
    </section>
  )
}

export interface JoinRequestsProps extends Common {
  space?: string
  /** Display a request (default: its name, or a shortened npub). */
  nameOf?: (r: JoinRequestInfo) => ReactNode
}

/** Requests waiting for an owner / admin, with approve / reject. */
export function JoinRequests(props: JoinRequestsProps) {
  const l = useLabels(props)
  const auth = useAnoAuth()
  const requests = useAuthQuery((a) => a.requests(props.space), [props.space])
  const { error, run } = useRun()
  if (!requests || requests.length === 0) return null
  return (
    <section className={props.className ?? 'anoauth-requests'} style={col}>
      <h3 style={{ margin: 0 }}>{l.requests}</h3>
      <ul style={list}>
        {requests.map((r) => (
          <li key={r.id} style={col}>
            <span>
              {props.nameOf ? props.nameOf(r) : r.name || `${r.npub.slice(0, 12)}…`} <span className="anoauth-badge">{r.role}</span>
              {r.proof && <span className="anoauth-hint"> {r.proof.subject}</span>}
            </span>
            {r.status === 'conflict' && <span className="anoauth-hint">{l.conflict}</span>}
            <span style={row}>
              <button className="anoauth-button" onClick={() => void run(auth.approve(r.id))}>
                {l.approve}
              </button>
              <button className="anoauth-button anoauth-secondary" onClick={() => void run(auth.reject(r.id))}>
                {l.reject}
              </button>
            </span>
          </li>
        ))}
      </ul>
      <ErrorText error={error} />
    </section>
  )
}

export interface RulesEditorProps extends Common {
  space: string
  /** Default issuer for OIDC rules. Default: Google. */
  defaultOidcIssuer?: string
}

const strip = ({ id: _id, active: _a, ...r }: StoredRule): Rule => r

/** Edit who may join a space (owners and admins; rules granting admin: owner only). */
export function RulesEditor(props: RulesEditorProps) {
  const l = useLabels(props)
  const auth = useAnoAuth()
  const rules = useAuthQuery((a) => a.rules(props.space), [props.space])
  const me = auth.db.roleIn(props.space)
  const { error, run } = useRun()
  const [proof, setProof] = useState<'link' | 'approval' | 'certificate' | 'oidc'>('approval')
  const [issuer, setIssuer] = useState('')
  const [cond, setCond] = useState<'any' | 'domain' | 'emails'>('any')
  const [value, setValue] = useState('')
  const [role, setRole] = useState<Rule['role']>('writer')
  if (!MANAGERS.has(me ?? '')) return null

  const describe = (r: StoredRule) => {
    const p = r.proof === 'link' ? l.proofLink : r.proof === 'approval' ? l.proofApproval : `${r.proof.type === 'oidc' ? l.proofOidc : l.proofCertificate}: ${[r.proof.issuer ?? ''].flat().join(', ')}`
    const c = r.emailDomain ? ` · ${l.domain} ${[r.emailDomain].flat().join(', ')}` : r.email ? ` · ${l.emails} ${r.email.join(', ')}` : ''
    return `${p}${c} → ${r.role}`
  }
  const save = (next: Rule[]) => run(auth.setRules(props.space, next))
  const add = () => {
    const values = value.split(',').map((s) => s.trim()).filter(Boolean)
    const r: Rule =
      proof === 'link' || proof === 'approval'
        ? { proof, role }
        : {
            proof: { type: proof, ...(issuer.trim() || proof === 'oidc' ? { issuer: issuer.trim() || props.defaultOidcIssuer || 'https://accounts.google.com' } : {}) },
            role,
            ...(cond === 'domain' && values.length ? { emailDomain: values } : {}),
            ...(cond === 'emails' && values.length ? { email: values } : {}),
          }
    void save([...(rules ?? []).map(strip), r]).then(() => setValue(''))
  }
  return (
    <section className={props.className ?? 'anoauth-rules'} style={col}>
      <h3 style={{ margin: 0 }}>{l.rules}</h3>
      {rules && rules.length === 0 && <span className="anoauth-hint">{l.noRules}</span>}
      <ul style={list}>
        {(rules ?? []).map((r, i) => (
          <li key={r.id} style={{ ...row, justifyContent: 'space-between' }}>
            <span>
              {i + 1}. {describe(r)} {!r.active && <span className="anoauth-hint">{l.inactive}</span>}
            </span>
            <button className="anoauth-button anoauth-secondary" onClick={() => void save((rules ?? []).filter((x) => x.id !== r.id).map(strip))}>
              {l.remove}
            </button>
          </li>
        ))}
      </ul>
      <form
        style={col}
        onSubmit={(e) => {
          e.preventDefault()
          add()
        }}
      >
        <select className="anoauth-select" value={proof} onChange={(e) => setProof(e.target.value as typeof proof)}>
          <option value="approval">{l.proofApproval}</option>
          <option value="link">{l.proofLink}</option>
          <option value="oidc">{l.proofOidc}</option>
          <option value="certificate">{l.proofCertificate}</option>
        </select>
        {(proof === 'oidc' || proof === 'certificate') && (
          <>
            <input className="anoauth-input" placeholder={proof === 'oidc' ? (props.defaultOidcIssuer ?? 'https://accounts.google.com') : l.issuer} value={issuer} onChange={(e) => setIssuer(e.target.value)} />
            <div style={row}>
              <select className="anoauth-select" value={cond} onChange={(e) => setCond(e.target.value as typeof cond)}>
                <option value="any">{l.anyEmail}</option>
                <option value="domain">{l.domain}</option>
                <option value="emails">{l.emails}</option>
              </select>
              {cond !== 'any' && <input className="anoauth-input" style={{ flex: 1, minWidth: 0 }} placeholder={l.value} value={value} onChange={(e) => setValue(e.target.value)} />}
            </div>
          </>
        )}
        <div style={row}>
          <select className="anoauth-select" aria-label={l.role} value={role} onChange={(e) => setRole(e.target.value as Rule['role'])}>
            <option value="writer">writer</option>
            <option value="reader">reader</option>
            {me === 'owner' && <option value="admin">admin</option>}
          </select>
          <button className="anoauth-button">{l.addRule}</button>
        </div>
      </form>
      <ErrorText error={error} />
    </section>
  )
}

// ---- applicants --------------------------------------------------------------------------------

/** A way for the applicant to prove something, e.g. `oidcProofSource(...)` from @anoauth/oidc. */
export interface ProofSource {
  type: string
  /** Button text, e.g. "Continue with Google". */
  label: string
  get(nonce: string, link: ParsedLink): Promise<ProofEnvelope>
}

export interface JoinWithLinkProps extends Common {
  proofs?: ProofSource[]
  onJoined?: (space: string) => void
  defaultName?: string
}

/** The applicant's side: open or paste a link, prove (if the space asks for it), then wait. */
export function JoinWithLink(props: JoinWithLinkProps) {
  const l = useLabels(props)
  const auth = useAnoAuth()
  const [incoming, clearIncoming] = useIncomingJoinLink()
  const [text, setText] = useState('')
  const [name, setName] = useState(props.defaultName ?? '')
  const [waitingFor, setWaitingFor] = useState<string | null>(null)
  const { error, setError, run } = useRun()
  const onJoined = props.onJoined

  useEffect(() => {
    if (incoming) setText(incoming)
  }, [incoming])
  useEffect(() => {
    if (!waitingFor) return
    const check = () => {
      if (auth.db.spaces().some((s) => s.id === waitingFor && s.status === 'active')) {
        setWaitingFor(null)
        onJoined?.(waitingFor)
      }
    }
    check()
    return auth.db.onChange(check)
  }, [auth, waitingFor, onJoined])

  const parsed = parseLink(text)
  const sources = (props.proofs ?? []).filter((s) => parsed?.accepts.includes(s.type))
  const send = async (source?: ProofSource) => {
    if (!parsed || parsed.appId !== auth.db.appId) return setError(l.invalidLink)
    const proofs = source ? [await source.get(await auth.nonceFor(text), parsed)] : []
    await auth.requestJoin(text, { name: name.trim(), proofs })
    setWaitingFor(parsed.space)
    clearIncoming()
  }

  return (
    <section className={props.className ?? 'anoauth-join'} style={col}>
      <h3 style={{ margin: 0 }}>{l.join}</h3>
      {waitingFor ? (
        <span className="anoauth-hint" role="status">
          {l.waiting}
        </span>
      ) : (
        <>
          <input className="anoauth-input" aria-label={l.inviteLink} placeholder={l.inviteLink} value={text} onChange={(e) => setText(e.target.value)} />
          <input className="anoauth-input" aria-label={l.yourName} placeholder={l.yourName} value={name} onChange={(e) => setName(e.target.value)} />
          <div style={row}>
            {sources.map((s) => (
              <button key={s.type} className="anoauth-button" onClick={() => void run(send(s))}>
                {s.label}
              </button>
            ))}
            <button className={sources.length ? 'anoauth-button anoauth-secondary' : 'anoauth-button'} disabled={!text.trim()} onClick={() => void run(send())}>
              {sources.length ? l.requestPlain : l.request}
            </button>
          </div>
        </>
      )}
      <ErrorText error={error} />
    </section>
  )
}

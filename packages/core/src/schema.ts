/**
 * Tables anoAuth keeps in anoDB. Add them to your schema:
 *
 *   defineSchema({ ...yourTables, ...anoauthTables })
 *
 * They live in three places:
 * - the **admin space** of a guarded space (members: its owner and admins): guard, rules, links,
 *   requests, admissions — regular members can neither read nor change them;
 * - the guarded space itself: `anoauthChannel` (where members send renewals);
 * - your personal space: `anoauthPending` (spaces you asked to join).
 */
export const anoauthTables = {
  anoauthGuard: { target: 'text' },
  anoauthRules: { position: 'integer', rule: 'json' },
  anoauthLinks: { secret: 'text', accepts: 'json', expiresAt: 'integer', singleUse: 'boolean', usedBy: 'text', revoked: 'boolean' },
  anoauthRequests: { link: 'text', identity: 'text', name: 'text', devices: 'json', role: 'text', status: 'text', proof: 'json', subjectKey: 'text' },
  anoauthAdmissions: { identity: 'text', proofType: 'text', issuer: 'text', subject: 'text', provedAt: 'integer', revalidateDays: 'integer' },
  anoauthChannel: { secret: 'text' },
  anoauthPending: { target: 'text' },
} as const

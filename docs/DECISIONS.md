# Decisions

| # | Topic | Decision |
|---|---|---|
| 1 | Boundary with anoDB (2026-11-15) | anoDB handles membership by public key only (anoDB DECISIONS 27). anoAuth decides *who* may join and calls `addMember` on an owner / admin device. Joiners hand over `db.deviceDelegations()` |
| 2 | Members (Q1) | Members are anoDB pubkeys. A space can also hold **reservations** for external identities (e.g. "alice@company.com as writer"); the first valid proof from that identity turns into membership of the proving pubkey |
| 3 | Who admits (Q2) | Only **owner / admin devices** verify proofs and admit, automatically and without a click. Other devices only check that an admin added the member, so membership is deterministic and writers cannot bypass the rules. Admission waits until an admin device is online |
| 4 | Entry point (Q3) | The **invite link** carries where to send the request and which proof types are accepted. Rule contents (e.g. email lists) stay encrypted in the space. Approval-only links behave like anoDB's former one-time links |
| 5 | Link lifetime (Q4) | Proof-based links are **reusable**, expire after 30 days by default (or never), and can be revoked. Approval-only links are single-use |
| 6 | Token age (Q5) | An OIDC ID token is accepted if **issued within 7 days** (configurable), ignoring its 1-hour `exp`. Its `nonce` must bind the applicant's pubkey, so a stolen token is useless for another key |
| 7 | Losing eligibility (Q6) | Members admitted by an external proof **re-prove every 90 days** (configurable, can be off). Without a fresh proof an admin device removes them and rotates the key. NIP-05 can be rechecked by the admin; OIDC is refreshed by the member's app, prompting only when needed. npub / link / approval members are exempt |
| 8 | First release (Q7) | Proof types: invite link, npub, manual approval, **signed certificate from a trusted issuer key** (the entry point for a future anoAuth issuer or a company system; verifiable offline), and **OIDC** (separate package). NIP-05 later. All are plugins of the same shape |

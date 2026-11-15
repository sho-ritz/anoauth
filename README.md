# anoAuth

**Who may join** a shared [anoDB](https://github.com/sho-ritz/anodb) space — invite links, admin approval,
sign-in with Google / Microsoft / your company's SSO, or certificates from an issuer you trust.

anoDB only knows public keys: it adds members (`addMember(space, npub, role, { devices })`), removes
them and delivers the encryption keys. anoAuth runs on an owner's or admin's device, decides whether a
request qualifies, and calls `addMember`. No server is required.

> **Status: design.** See [docs/DECISIONS.md](docs/DECISIONS.md).

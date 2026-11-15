# @anoauth/cli

The anoAuth **gatekeeper**: an always-on admin device that admits join requests matching a space's
rules while your admins are offline.

```sh
npx @anoauth/cli gatekeeper --app com.example.app --trust npub1owner…
# then, from the owner's app: db.addMember(space, '<gatekeeper npub>', 'admin')
```

The gatekeeper is an admin, so it can read the spaces it guards: run it on a machine you trust.
See the [anoAuth README](https://github.com/sho-ritz/anoauth#readme).

# Gift lists: Wishlist and Pønskelisten against the floor (2026-11-24)

The household keeps its gift lists in a Google Sheet. This note checks the two open-source candidates for the
purpose "gift lists" (wave #120, family apps; two apps per purpose, #127) against the floor and the app definition,
and records the maintainer's decisions of 2026-11-24.

Read at: cmintey/wishlist `main` 0be4f4e (2026-11-17) and tag v0.69.0; aunefyren/poenskelisten v2.7.0 (84f7085,
2026-11-14).

## What the household asked for

- One list per person; the person a list is for never learns what was claimed or bought.
- Adults, kids, guests (relatives until a date) and, for some lists, anyone with a link.
- A kid's list gets a public link only with an adult's approval.
- The sheet's 47 items imported once; the sheet is then retired.

## The two apps

| | Wishlist (cmintey) | Pønskelisten (aunefyren) |
|---|---|---|
| Licence | MIT | GPL-3.0 (`LICENSE`) |
| Stack | SvelteKit + Prisma, SQLite; its own Caddy inside the image on 3280 | Go, SQLite (or Postgres, MySQL) on 8080 |
| Sign-in | OIDC, all of it settable from the environment (`OIDC_*`); admin from a groups claim at every sign-in; password login and sign-up can be switched off (`SECURITY_DISABLE_PASSWORD_LOGIN`, `ENABLE_SIGNUP`) | OIDC (`oidc*` variables), auto-create optional; local passwords with optional TOTP |
| Claims hidden from the owner | **On screen only.** The owner's list page data (`toItemOnListDTO`) and the live updates (`/lists/<id>/events`) carry every claim: who claimed it and whether it was bought. `?filter=` works on claims too. | **On the server.** Claim details are purged for the owner (`controllers/wish_test.go`: "claim details purged for the wishlist owner"); the owner can't claim their own wishes. |
| Public links | Per list, when the admin allows public lists; "registry" groups are always public | Any wishlist can be shared publicly |
| Kid view | None | None |
| Runs as | root (no `USER`); writes caches under HOME at start | drops to `PUID`/`PGID` at start (`su-exec`) |
| Data | `/usr/src/app/data` (`prod.db`), `/usr/src/app/uploads` (pictures) | `/app/files` (config, log, `data.db`), `/app/images` |
| Health | No endpoint; a static file (`/favicon.ico`) answers through the app | No endpoint; `/api/open/...` routes answer without sign-in |
| Outbound | Fetches product pages for "add from URL" (`/api/product`, with an SSRF guard in `safeurl.ts`) | None needed |
| Extras | the outbound fetch is optional: without network it fails and the wish is typed by hand | none |

Both meet the floor once wired (no published port, not privileged, pinned digest, declared data and secrets,
OIDC sign-in). Neither has a health endpoint or a kid view.

## The finding that matters

The household's first requirement is the surprise. Wishlist keeps it only from people who don't open the browser's
developer tools: on their own list, the page's JSON names everyone who claimed a wish and whether it was bought.
Pønskelisten keeps it on the server and tests it.

## Decisions (the maintainer, 2026-11-24)

- **Wishlist first**, with a patch that strips claims for the owner on the server. Pønskelisten is the second app
  for the purpose.
- The patch is `claims-hidden.patch` (classic: `wishlist/claims-hidden.patch` on branch `handover/gift-lists`):
  `getItems` and the two item event handlers send the owner no claims, before filtering and sorting; managers and
  "not for me" lists keep upstream's behaviour. It applies to v0.69.0 and `main`.
- **This is not a sign-in patch.** ADR 0015 allows feedstocks only where sign-in needs one. Carrying this patch in a
  feedstock needs ADR 0015 amended (or the patch upstream first, which ADR 0015 asks for anyway).
- **Classic now, HomersLab later.** Christmas 2026 comes before HomersLab's first install path, so classic gets the
  component `gifts` (gifts.<domain>), built locally like Memos. The app definition below waits for the manifest code.
- **Import once**, with a one-off script kept in the maintainer's private repository; the sheet is retired after.
- **Kids' public lists need an adult.** Neither app can enforce that. Until a patch does, public lists stay off.

## Settings that matter in Wishlist

- Claims, "show to the owner": off (the patch relies on it).
- Suggestions: "Approval required". Not "Surprise me": that mode hides from the owner every item someone else added,
  decided at every read (`getItems`, `addedById`), so wishes imported or added for someone vanish from their own list.
- Public lists: off, until the kid rule exists.
- Groups claim: Wishlist asks for the `groups` scope when an admin group is set. Whether the identity provider
  refuses an unknown scope or ignores it needs a test with each provider (Authentik, Kanidm).

## Draft app definition (Wishlist)

The manifest's format isn't code yet; this follows the spec's "The app definition" and ADR 0009. Values in angle
brackets come from the feedstock's CI.

```yaml
# app.yaml (draft)
id: wishlist
name: Gifts
description: Wish lists for the family. Others claim gifts; the person they're for never sees it.
category: family
tier: verified            # once the sign-in, restore and update tests pass
versions:
  docker:
    amd64: ghcr.io/homerslab/feedstock-wishlist@sha256:<digest>   # v0.69.0 + claims-hidden.patch
    arm64: ghcr.io/homerslab/feedstock-wishlist@sha256:<digest>
  signer: <the feedstock workflow's Sigstore identity>
sign-in:
  - method: oidc
    redirect: /login
    scopes: [openid, profile, email, groups]
    env:                  # what the manager sets
      OIDC_ENABLE: "true"
      OIDC_DISCOVERY_URL: "{issuer}"
      OIDC_CLIENT_ID: "{client_id}"
      OIDC_CLIENT_SECRET: "{secret:oidc}"
      OIDC_PROVIDER_NAME: "{household}"
      OIDC_AUTO_REDIRECT: "true"
      OIDC_AUTO_REGISTER: "true"
      OIDC_ENABLE_SYNC: "true"
      OIDC_ADMIN_GROUP: "{group:admin}"
      SECURITY_DISABLE_PASSWORD_LOGIN: "true"
      ENABLE_SIGNUP: "false"
names:
  default: gifts
  exposure: mesh
  public: allowed         # public list links; kids' lists only with an adult (needs a patch)
audience:
  default: [admin, adult, kid]
  kid-view: none          # the same app; public lists off for kids
data:
  - path: /usr/src/app/data
    sqlite: [prod.db]
  - path: /usr/src/app/uploads
secrets:
  - id: oidc
    generate: random-48
health:
  http: /favicon.ico      # no health endpoint upstream; offer one upstream
resources:
  memory: 512Mi
  disk: 1Gi
extras:
  - network: outbound     # optional: "add from URL" fetches the shop's page
people:
  end-sessions: <no API: remove the account in the identity provider; Wishlist's sessions end at expiry>
  export: <none upstream>
update-notes: Built from upstream's tag with claims-hidden.patch; the build stops if the patch no longer applies.
```

```yaml
# compose.yaml (draft): no ports, not privileged
services:
  app:
    image: "{image}"
    user: "{uid}:{gid}"
    read_only: true
    tmpfs: [/tmp]
    environment:
      HOME: /tmp
      XDG_DATA_HOME: /tmp
      XDG_CONFIG_HOME: /tmp
      ORIGIN: "https://{name}"
      DEFAULT_CURRENCY: "{currency}"
    volumes:
      - data:/usr/src/app/data
      - uploads:/usr/src/app/uploads
volumes:
  data: {}
  uploads: {}
```

Open for the definition: the `people` section (Wishlist has no API to end one person's sessions), a real health
check (offer upstream), the `groups` scope question above, and whether it runs read-only as a non-root UID (classic's
draft does; not yet run).

## Sources

- github.com/cmintey/wishlist: README (OIDC variables, registry mode, suggestions), `src/lib/server/list.ts`
  (`getItems`), `src/lib/dtos/item-mapper.ts` (`toItemOnListDTO`), `src/lib/events.ts`,
  `src/routes/lists/[id]/events/+server.ts`, `src/lib/components/wishlists/ItemCard/ClaimButtons.svelte`
  (`showClaimForOwner`), `Dockerfile`, `entrypoint.sh`, `Caddyfile`.
- github.com/aunefyren/poenskelisten: README (configuration table, `files/` and `images/`), `Dockerfile`,
  `entrypoint.sh`, `main.go` (routes), `controllers/wish_test.go` (claims purged for the owner).

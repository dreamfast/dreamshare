# DreamShare

Secure link based file and text sharing with browser side end to end
encryption. Go plus a Vue SPA, SQLite metadata, Backblaze B2 for ciphertext.
The link is the key, lose it and the file is gone. There is no recovery.

## Dev quickstart

```sh
cp .env.example .env   # fill in the b2 section, minio works for dev
make tools
make ci
make run               # serves /healthz and /readyz
```

## The secure context trap

WebCrypto only exists in a secure context. `http://localhost` and
`http://127.0.0.1` are both fine, loopback is exempt. Opening the dev server
as `http://<lan-ip>` silently disables encryption instead. Use localhost or
real tls when testing from another device.

## Layout

- `cmd/dreamshare` wiring only
- `internal/config` fail closed environment loader
- `internal/storage/sqlite` migrations and the two pools, one writer
- `web` the Vue SPA, joins in a later slice

`make ci` is the go gate, identical commands locally and in CI. Two extra
checks run in CI only, gitleaks for secrets and the build on a clean cache,
because neither is meaningful on a warm dev box.

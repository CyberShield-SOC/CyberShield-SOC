# Local dev HTTPS certificate

This folder holds a locally-trusted TLS certificate for `npm run dev` /
`npm run preview`, generated with [mkcert](https://github.com/FiloSottile/mkcert).
The `.pem` files are gitignored (they're machine-specific and worthless to
anyone but the machine that trusts their CA) -- each developer generates
their own once.

## One-time setup

```
# Install mkcert (pick one)
winget install --id FiloSottile.mkcert -e
choco install mkcert

# Install mkcert's local CA into your OS + browser trust stores.
# This is the one step that changes system trust settings, so do it
# yourself rather than through an automated agent.
mkcert -install

# From frontend/.cert/, generate the leaf certificate this config expects:
cd frontend/.cert
mkcert -cert-file localhost.pem -key-file localhost-key.pem localhost 127.0.0.1 ::1
```

After that, `npm run dev` and `npm run preview` (see `vite.config.js`) pick
the cert up automatically and both of these load with a trusted padlock,
no browser warning:

- https://localhost:5173/
- https://127.0.0.1:5173/

If `localhost.pem`/`localhost-key.pem` are missing (e.g. a fresh clone
before running the steps above), Vite falls back to its own transient
self-signed certificate -- the dev server still starts, just with the
"Not secure" warning this setup exists to avoid.

Production deployments are unaffected: this cert is dev-server-only and
`vite build` output is served behind whatever real TLS terminator/reverse
proxy the deployment uses.

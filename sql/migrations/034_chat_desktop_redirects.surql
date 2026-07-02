-- The desktop (Electron) build shares the neoworks-chat OAuth client with the
-- mobile/browser build. Add its redirect URIs: Vite dev origin, the https caddy
-- domain, and the packaged app:// protocol origin used in production.
UPDATE client:`neoworks-chat` SET redirect_uris = array::distinct(array::concat(redirect_uris, [
    "http://localhost:5180/callback",
    "https://chat-desktop.neoworks.localhost/callback",
    "app://chat/callback"
]));

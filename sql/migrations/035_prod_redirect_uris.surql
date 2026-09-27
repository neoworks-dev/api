-- Production redirect URIs (neoworks.dev). Appended alongside the existing dev
-- (*.neoworks.localhost) and native custom-scheme URIs so flipping BASE_DOMAIN to
-- neoworks.dev doesn't break the OAuth redirect validation. Idempotent via
-- array::distinct.

UPDATE client:`neoworks.dev` SET redirect_uris = array::distinct(array::concat(redirect_uris, [
    "https://neoworks.dev/auth/callback"
]));

UPDATE client:`neoworks-calendar` SET redirect_uris = array::distinct(array::concat(redirect_uris, [
    "https://calendar.neoworks.dev/callback"
]));

UPDATE client:`neoworks-contacts` SET redirect_uris = array::distinct(array::concat(redirect_uris, [
    "https://contacts.neoworks.dev/callback"
]));

UPDATE client:`neoworks-photos` SET redirect_uris = array::distinct(array::concat(redirect_uris, [
    "https://photos.neoworks.dev/callback"
]));

UPDATE client:`neoworks-maps` SET redirect_uris = array::distinct(array::concat(redirect_uris, [
    "https://maps.neoworks.dev/callback"
]));

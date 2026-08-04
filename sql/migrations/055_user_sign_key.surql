-- ── Account signing key ───────────────────────────────────────────────────────
-- Ed25519 public key derived (client-side, in the Vault) from the AMK:
-- crypto_sign_seed_keypair(blake2b(32, AMK, "nw-space-signing-v1")). The same
-- identity signs from every device, so peers pin one key per user. Used to sign
-- space item envelopes and wrapped space keys. The private key is never stored —
-- re-derived from the AMK on each unlock.
DEFINE FIELD sign_public_key ON user_key TYPE option<string>;

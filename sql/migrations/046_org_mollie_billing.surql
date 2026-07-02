-- Mollie billing on organizations. An org becomes a Mollie customer the first
-- time it sets up a payment method; the customer id is stored so later
-- usage-based charges reuse the mandate captured by the first payment.
--   mandate_status: none    — no payment method captured yet
--                   pending — a first payment was started, awaiting Mollie webhook
--                   valid   — first payment paid, a reusable mandate exists
--                   invalid — first payment failed/expired/canceled
DEFINE FIELD mollie_customer_id    ON organization TYPE option<string>;
DEFINE FIELD mollie_mandate_status ON organization TYPE option<string>
    ASSERT $value IN ["none", "pending", "valid", "invalid"];

DEFINE INDEX idx_org_mollie_customer ON organization FIELDS mollie_customer_id;

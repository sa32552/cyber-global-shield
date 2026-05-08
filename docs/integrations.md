# Sentry Integration Flow

## Example flow

1. Sentry sends webhook payload to `POST /api/v1/ingest/sentry`
2. API maps payload into canonical event:

```json
{
  "type": "error",
  "service": "checkout-api",
  "timestamp": 1710000000000,
  "message": "Stripe charge creation failed",
  "metadata": {
    "event_id": "abc123",
    "level": "error",
    "tags": {
      "release": "checkout-api@2026.04.14.1"
    }
  }
}
```

3. Event is fingerprinted and attached to an `incident_group`
4. If thresholds are crossed, an `incident` is created or updated
5. AI engine receives grouped logs and metrics
6. Dashboard receives WebSocket updates:
   - `incident:new`
   - `incident:updated`
   - `incident:analysis_completed`

## Revenue mapping

- Stripe and Shopify integrations enrich business context
- Impact model uses:
  - failed requests
  - average order value
  - conversion rate
- Formula:

```text
loss = failed_requests * avg_order_value * conversion_rate
```
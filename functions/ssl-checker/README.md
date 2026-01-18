# SSL Certificate Checker (Deno Deploy)

A Deno Deploy function that checks HTTPS status and full certificate details for a given host.

## Setup

1. Create an account at [dash.deno.com](https://dash.deno.com/)

2. Create a new project and link your GitHub repository

3. Set the entrypoint to: `functions/ssl-checker/main.ts`

4. Deploy!

See the deno dashboard for worker URL location

## Usage

```
GET https://<project-name>.deno.net/?host=example.com
```

### Response

```json
{
  "host": "example.com",
  "status": "online",
  "httpStatus": 200,
  "certificate": {
    "subject": "example.com",
    "issuer": "R3, Let's Encrypt",
    "validFrom": "2026-01-01T00:00:00.000Z",
    "validTo": "2026-04-01T00:00:00.000Z",
    "daysRemaining": 73,
    "isValid": true,
    "serialNumber": "03:AB:CD:..."
  },
  "tls": {
    "version": "TLSv1.3",
    "protocol": "h2"
  },
  "responseTimeMs": 145,
  "checkedAt": "2026-01-18T12:00:00.000Z"
}
```

## Local Development

Run locally with Deno:

```bash
cd functions/ssl-checker
deno run --allow-net main.ts
```

Then test with:
```bash
curl "http://localhost:8000/?host=google.com"
```

## Configuration

Update `ALLOWED_ORIGINS` in `main.ts` to add more allowed origins for CORS.

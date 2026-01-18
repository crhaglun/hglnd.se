/**
 * Deno Deploy: SSL Certificate Checker
 *
 * Usage: GET /?host=example.com
 * Returns full certificate details and response time
 *
 * Deploy: Link GitHub repo to Deno Deploy, set entrypoint to functions/ssl-checker/main.ts
 */

const ALLOWED_ORIGINS = [
  "https://hglnd.se",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
];

Deno.serve(async (request: Request): Promise<Response> => {
  const url = new URL(request.url);
  const origin = request.headers.get("Origin") || "";

  // CORS headers
  const corsHeaders: Record<string, string> = {
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };

  // Only allow configured origins
  if (ALLOWED_ORIGINS.includes(origin)) {
    corsHeaders["Access-Control-Allow-Origin"] = origin;
  }

  // Handle preflight
  if (request.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  // Only allow GET
  if (request.method !== "GET") {
    return jsonResponse({ error: "Method not allowed" }, 405, corsHeaders);
  }

  // Get host parameter
  const host = url.searchParams.get("host");
  if (!host) {
    return jsonResponse({ error: 'Missing "host" parameter' }, 400, corsHeaders);
  }

  // Validate host (basic sanitization)
  if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
    return jsonResponse({ error: "Invalid host format" }, 400, corsHeaders);
  }

  try {
    const result = await checkCertificate(host);
    return jsonResponse(result, 200, corsHeaders);
  } catch (err) {
    return jsonResponse(
      {
        host,
        error: err instanceof Error ? err.message : "Unknown error",
        status: "error",
      },
      200,
      corsHeaders
    );
  }
});

interface CertificateResult {
  host: string;
  status: "online" | "error";
  httpStatus?: number;
  certificate?: {
    subject: string;
    issuer: string;
    validFrom: string;
    validTo: string;
    daysRemaining: number;
    isValid: boolean;
    serialNumber: string;
  };
  tls?: {
    version: string;
    protocol: string;
  };
  responseTimeMs: number;
  checkedAt: string;
  error?: string;
}

async function checkCertificate(host: string): Promise<CertificateResult> {
  const startTime = Date.now();
  const port = 443;

  // Connect with TLS to get certificate info
  const conn = await Deno.connectTls({
    hostname: host,
    port,
  });

  // Get peer certificate
  const cert = conn.peerCertificate;
  const handshake = conn.handshake;

  // Make HTTP request to check status
  let httpStatus: number | undefined;
  try {
    const response = await fetch(`https://${host}/`, {
      method: "HEAD",
    });
    httpStatus = response.status;
  } catch {
    // Site might not respond to HEAD, that's ok
  }

  const responseTimeMs = Date.now() - startTime;

  // Close the connection
  conn.close();

  // Calculate days remaining
  const validTo = cert ? new Date(cert.expiresAt) : new Date();
  const now = new Date();
  const daysRemaining = Math.floor(
    (validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
  );

  return {
    host,
    status: "online",
    httpStatus,
    certificate: cert
      ? {
          subject: cert.subject || host,
          issuer: cert.issuer || "Unknown",
          validFrom: new Date(cert.issuedAt).toISOString(),
          validTo: validTo.toISOString(),
          daysRemaining,
          isValid: daysRemaining > 0,
          serialNumber: cert.serialNumber || "Unknown",
        }
      : undefined,
    tls: handshake
      ? {
          version: handshake.tlsVersion || "Unknown",
          protocol: handshake.alpnProtocol || "Unknown",
        }
      : undefined,
    responseTimeMs,
    checkedAt: new Date().toISOString(),
  };
}

function jsonResponse(
  data: unknown,
  status = 200,
  extraHeaders: Record<string, string> = {}
): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...extraHeaders,
    },
  });
}

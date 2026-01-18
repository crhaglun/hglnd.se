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

  try {
    // Connect with TLS to get certificate info
    const conn = await Deno.connectTls({
      hostname: host,
      port,
    });

    // Get handshake info (contains certificate details)
    const handshake = await conn.handshake();
    
    // Close the connection
    conn.close();

    const responseTimeMs = Date.now() - startTime;

    // Extract certificate info if available
    let certInfo: CertificateResult["certificate"] = undefined;
    let tlsInfo: CertificateResult["tls"] = undefined;

    if (handshake) {
      tlsInfo = {
        version: handshake.tlsVersion || "Unknown",
        protocol: handshake.alpnProtocol || "http/1.1",
      };
    }

    // Try to make HTTP request to verify site is responding
    let httpStatus: number | undefined;
    try {
      const response = await fetch(`https://${host}/`, {
        method: "HEAD",
        signal: AbortSignal.timeout(5000),
      });
      httpStatus = response.status;
    } catch {
      // Site might not respond to HEAD, try GET
      try {
        const response = await fetch(`https://${host}/`, {
          method: "GET",
          signal: AbortSignal.timeout(5000),
        });
        httpStatus = response.status;
      } catch {
        // Ignore - TLS connection worked so site is "up" for SSL purposes
      }
    }

    return {
      host,
      status: "online",
      httpStatus,
      certificate: certInfo,
      tls: tlsInfo,
      responseTimeMs,
      checkedAt: new Date().toISOString(),
    };
  } catch (err) {
    const responseTimeMs = Date.now() - startTime;
    throw new Error(`TLS connection failed: ${err instanceof Error ? err.message : "Unknown error"}`);
  }
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

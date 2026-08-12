import { BLOCKLIST } from './constants';

const UPSTREAM_DOH = env.UPSTREAM_DOH || 'https://one.one.one.one/dns-query';

// --- LOGIC ---

function isDomainBlocked(fullDomain: string): boolean {
  if (!fullDomain) return false;
  const parts = fullDomain.toLowerCase().split('.');
  while (parts.length > 0) {
    const check = parts.join('.');
    if (BLOCKLIST.has(check)) return true;
    parts.shift();
  }
  return false;
}

function extractDomainFromPacket(buffer: ArrayBuffer): string | null {
  try {
    const u8 = new Uint8Array(buffer);
    if (u8.length <= 12) return null;
    let offset = 12;
    const labels: string[] = [];
    while (offset < u8.length) {
      const length = u8[offset];
      if (length === 0) break;
      if ((length & 0xc0) === 0xc0) break;
      offset++;
      if (offset + length > u8.length) return null;
      const labelBytes = u8.slice(offset, offset + length);
      labels.push(new TextDecoder().decode(labelBytes));
      offset += length;
    }
    return labels.join('.');
  } catch (err) {
    return null;
  }
}

function base64UrlToBuffer(base64url: string): Uint8Array {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (base64.length % 4)) % 4;
  const paddedBase64 = base64 + '='.repeat(padLen);
  const binaryString = atob(paddedBase64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

// --- HANDLER ---

async function handleDohRequest(request: Request, packetBuffer: ArrayBuffer) {
  const domain = extractDomainFromPacket(packetBuffer);

  if (domain && isDomainBlocked(domain)) {
    console.log(`[DoH] BLOCKED: ${domain}`);
    return new Response(
      JSON.stringify({ error: `Domain '${domain}' is blocked.` }),
      { status: 403, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const upstreamHeaders: HeadersInit = {
    'Content-Type': 'application/dns-message',
    'Accept': 'application/dns-message',
  };

  const clientIP = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For');
  if (clientIP) {
    upstreamHeaders['X-Forwarded-For'] = clientIP;
  }

  const upstreamResponse = await fetch(UPSTREAM_DOH, {
    method: 'POST',
    body: packetBuffer,
    headers: upstreamHeaders,
  });

  if (!upstreamResponse.ok) {
    return new Response(
      JSON.stringify({ error: `Upstream error: ${upstreamResponse.statusText}` }),
      { status: upstreamResponse.status, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const data = await upstreamResponse.arrayBuffer();

  return new Response(data, {
    status: 200,
    headers: {
      'Content-Type': 'application/dns-message',
      'Cache-Control': upstreamResponse.headers.get('Cache-Control') || 'public, max-age=60',
    },
  });
}

// --- WORKER ---

export default {
  async fetch(request: Request, env: { FILTER_LIST: string }) {
    const { method, headers, url } = request;

    if (new URL(url).pathname !== '/dns-query') {
      return new Response('Not Found', { status: 404 });
    }

    if (method === 'POST' && headers.get('content-type') === 'application/dns-message') {
      const buffer = await request.arrayBuffer();
      return handleDohRequest(request, buffer);
    }

    if (method === 'GET') {
      const { searchParams } = new URL(url);
      const dnsParam = searchParams.get('dns');

      if (!dnsParam) {
        return new Response(JSON.stringify({ error: 'Missing dns parameter' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      try {
        const buffer = base64UrlToBuffer(dnsParam);
        return handleDohRequest(request, buffer.slice().buffer);
      } catch (e) {
        return new Response(JSON.stringify({ error: 'Invalid DNS parameter encoding' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    return new Response(JSON.stringify({ error: 'Invalid DoH request' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  },
};

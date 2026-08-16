import { BLOCKLIST } from './constants';

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
      if ((length & 0xc0) === 0xc0) break; // Pointer
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

/**
 * Constructs an NXDOMAIN DNS response based on the incoming query packet.
 */
function createNXDOMAINResponse(requestBuffer: ArrayBuffer): Uint8Array | null {
  const u8 = new Uint8Array(requestBuffer);
  if (u8.length < 12) return null;

  // Extract QDCOUNT (number of questions)
  const qdcount = (u8[4] << 8) | u8[5];
  if (qdcount === 0) return null;

  // Find the end of the Question section to slice our response
  let offset = 12;
  while (offset < u8.length) {
    const length = u8[offset];
    if (length === 0) {
      offset += 1;
      break;
    }
    if ((length & 0xc0) === 0xc0) {
      offset += 2;
      break;
    }
    offset += length + 1;
  }
  
  // Add 4 bytes for QTYPE and QCLASS
  offset += 4;
  if (offset > u8.length) return null;

  // Create the response buffer copying only the Header + Question section
  const res = new Uint8Array(offset);
  res.set(u8.slice(0, offset));

  // Modify Header Flags (Bytes 2 & 3)
  // Byte 2: QR(1), Opcode(from req), AA(0), TC(0), RD(from req)
  const isRD = (u8[2] & 0x01) !== 0; // Check Recursion Desired bit
  const opcode = u8[2] & 0x78; // Keep original Opcode
  res[2] = 0x80 | opcode | (isRD ? 0x01 : 0x00);

  // Byte 3: RA(1), Z(0), RCODE(3 for NXDOMAIN)
  res[3] = 0x80 | 0x03;

  // Ensure ANCOUNT, NSCOUNT, ARCOUNT are 0 (Bytes 6 through 11)
  res[6] = 0; res[7] = 0;
  res[8] = 0; res[9] = 0;
  res[10] = 0; res[11] = 0;

  return res;
}

function base64UrlToBuffer(base64url: string): Uint8Array {
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }

  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

// --- HANDLER ---
async function handleDohRequest(request: Request, packetBuffer: ArrayBuffer, env: any) {
  const domain = extractDomainFromPacket(packetBuffer);
  const UPSTREAM_DOH = env.UPSTREAM_DOH || 'https://one.one.one.one/dns-query';
  
  if (domain && isDomainBlocked(domain)) {
    console.log(`[DoH] BLOCKED: ${domain}`);
    
    const nxdomainBuf = createNXDOMAINResponse(packetBuffer);
    if (!nxdomainBuf) {
      return new Response(JSON.stringify({ error: 'Malformed DNS query' }), { 
        status: 400, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    // DoH specifies that even blocked/failed resolution should return HTTP 200 OK 
    // as long as the DNS wire format inside is valid.
    return new Response(nxdomainBuf, {
      status: 200,
      headers: {
        'Content-Type': 'application/dns-message',
        'Cache-Control': 'public, max-age=300', // Cache NXDOMAIN for 5 mins (optional)
      },
    });
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
  async fetch(request: Request, env: any) {
    const { method, headers, url } = request;

    if (new URL(url).pathname !== '/dns-query') {
      return new Response('Not Found', { status: 404 });
    }

    if (method === 'POST' && headers.get('content-type') === 'application/dns-message') {
      const buffer = await request.arrayBuffer();
      return handleDohRequest(request, buffer, env); 
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
        const uint8Array = base64UrlToBuffer(dnsParam);
        const arrayBuffer = uint8Array.buffer.slice(
          uint8Array.byteOffset,
          uint8Array.byteOffset + uint8Array.byteLength
        );
        return handleDohRequest(request, arrayBuffer, env);
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

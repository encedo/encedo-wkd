import hashlib


# Z-Base-32 alphabet — differs from standard Base32!
ZBASE32_ALPHABET = 'ybndrfg8ejkmcpqxot1uwisza345h769'


def zbase32_encode(data: bytes) -> str:
    """Z-Base-32 encoding (WKD-specific alphabet per RFC draft)."""
    result = []
    buffer = 0
    bits = 0
    for byte in data:
        buffer = (buffer << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            result.append(ZBASE32_ALPHABET[(buffer >> bits) & 0x1f])
    if bits > 0:
        result.append(ZBASE32_ALPHABET[(buffer << (5 - bits)) & 0x1f])
    return ''.join(result)


def wkd_hash(local_part: str) -> str:
    """Compute WKD hash for the local part of an email address."""
    digest = hashlib.sha1(local_part.lower().encode()).digest()
    return zbase32_encode(digest)


def extract_domain(request) -> str:
    """Extract domain from X-Forwarded-Host or Host header, stripping 'openpgpkey.' prefix.

    Compatible with stdlib http.server.BaseHTTPRequestHandler (headers dict-like).
    """
    host = request.headers.get('X-Forwarded-Host') or request.headers.get('Host', '')
    domain = host.split(':')[0]
    if domain.startswith('openpgpkey.'):
        domain = domain[len('openpgpkey.'):]
    return domain

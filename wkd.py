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


def extract_uids(pubkey_bytes: bytes) -> list[str]:
    """Extract all User ID strings from a binary OpenPGP key (RFC 4880 §5.11).

    Handles both old-format (bit 6 = 0) and new-format (bit 6 = 1) packets.
    Returns a list of UTF-8 UID strings found in the packet stream.
    """
    uids = []
    i = 0
    n = len(pubkey_bytes)
    while i < n:
        b = pubkey_bytes[i]
        if not (b & 0x80):
            break  # not a valid packet header
        i += 1
        if b & 0x40:
            # New format: bits 5-0 = tag
            tag = b & 0x3F
            if i >= n:
                break
            first = pubkey_bytes[i]; i += 1
            if first < 192:
                length = first
            elif first < 224:
                if i >= n:
                    break
                length = ((first - 192) << 8) + pubkey_bytes[i] + 192; i += 1
            elif first == 255:
                if i + 4 > n:
                    break
                length = int.from_bytes(pubkey_bytes[i:i + 4], 'big'); i += 4
            else:
                break  # partial-body length — not expected in stored keys
        else:
            # Old format: bits 5-2 = tag, bits 1-0 = length type
            tag = (b & 0x3C) >> 2
            ltype = b & 0x03
            if ltype == 0:
                if i >= n:
                    break
                length = pubkey_bytes[i]; i += 1
            elif ltype == 1:
                if i + 2 > n:
                    break
                length = int.from_bytes(pubkey_bytes[i:i + 2], 'big'); i += 2
            elif ltype == 2:
                if i + 4 > n:
                    break
                length = int.from_bytes(pubkey_bytes[i:i + 4], 'big'); i += 4
            else:
                break  # indeterminate length — skip
        if i + length > n:
            break
        body = pubkey_bytes[i:i + length]
        i += length
        if tag == 13:  # User ID packet
            try:
                uids.append(body.decode('utf-8'))
            except UnicodeDecodeError:
                pass
    return uids


def extract_domain(request) -> str:
    """Extract domain from X-Forwarded-Host or Host header, stripping 'openpgpkey.' prefix.

    Compatible with stdlib http.server.BaseHTTPRequestHandler (headers dict-like).
    """
    host = request.headers.get('X-Forwarded-Host') or request.headers.get('Host', '')
    domain = host.split(':')[0]
    if domain.startswith('openpgpkey.'):
        domain = domain[len('openpgpkey.'):]
    return domain

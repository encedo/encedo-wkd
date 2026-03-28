import os
import base64
import logging

log = logging.getLogger(__name__)

_cache_dir = "/var/encedo-wkd/cache"


def init(cache_dir: str) -> None:
    global _cache_dir
    _cache_dir = cache_dir
    os.makedirs(_cache_dir, exist_ok=True)


def _key_path(domain: str, hash_: str) -> str:
    return os.path.join(_cache_dir, domain, hash_)


def get_key(domain: str, hash_: str) -> bytes | None:
    path = _key_path(domain, hash_)
    if not os.path.isfile(path):
        return None
    with open(path, 'rb') as f:
        return f.read()


def put_key(domain: str, hash_: str, pubkey_bytes: bytes) -> None:
    dir_ = os.path.join(_cache_dir, domain)
    os.makedirs(dir_, exist_ok=True)
    path = os.path.join(dir_, hash_)
    with open(path, 'wb') as f:
        f.write(pubkey_bytes)
    log.info("stored key for domain=%s hash=%s (%d bytes)", domain, hash_, len(pubkey_bytes))


def delete_key(domain: str, hash_: str) -> bool:
    path = _key_path(domain, hash_)
    if os.path.isfile(path):
        os.remove(path)
        log.info("deleted key for domain=%s hash=%s", domain, hash_)
        return True
    return False


def decode_pubkey(pubkey_base64: str) -> bytes:
    """Decode base64-encoded binary OpenPGP pubkey."""
    return base64.b64decode(pubkey_base64)

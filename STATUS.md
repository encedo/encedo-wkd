# encedo-wkd — Status wdrożenia

## Stan: PRODUKCJA ✅

Ostatnia aktualizacja: 2026-03-29

---

## Serwer

- **Host:** mailserver.encedo.com (`65.21.170.222`)
- **Usługa:** `/etc/systemd/system/encedo-wkd.service` — running, enabled
- **Pliki Python:** `/opt/encedo-wkd/`
- **Cache kluczy:** `/var/encedo-wkd/cache/`
- **Config:** `/opt/encedo-wkd/config.json`
- **Port:** `127.0.0.1:8089`

## Domeny WKD

| Domena | DNS CNAME | Cert | Test |
|--------|-----------|------|------|
| openpgpkey.encedo.com | ✅ | ✅ Let's Encrypt | ✅ 200 OK |
| openpgpkey.kress-net.com | ✅ | ✅ Let's Encrypt | ✅ 200 OK |
| openpgpkey.eight-lex.pl | ✅ | ✅ Let's Encrypt | ✅ 200 OK |

## Testy

- `curl https://openpgpkey.encedo.com/.well-known/openpgpkey/policy` → `200 OK` ✅
- `gpg --auto-key-locate clear,wkd --locate-key krzysztof@encedo.com` → klucz pobrany ✅

---

## Architektura nginx

Carbonio nginx (`/opt/zextras/common/sbin/nginx`):

```
nginx.conf.web.https       ← nasz plik (generowany przez inject.sh)
  server { listen 65.21.170.222:443 ssl; server_name openpgpkey.*; }
  → proxy_pass http://127.0.0.1:8089

nginx.conf.web.https.default  ← Carbonio default
  server { listen 65.21.170.222:443 default_server; server_name mailserver.*; }
```

**Kluczowe:** `listen 65.21.170.222:443` (nie `*:443`) — musi być ten sam socket
co `default_server` Carbonio, inaczej SNI nie działa.

## API Publish (przez główną domenę Carbonio)

```
POST https://mailserver.encedo.com/wkd/api/publish
X-Auth-Token: <carbonio_session_token>

nginx extensions/backend-wkd.conf → location /wkd/ → proxy → 127.0.0.1:8089
server.py → walidacja tokenu przez Carbonio SOAP GetInfoRequest
→ zapisuje /var/encedo-wkd/cache/<domain>/<wkd_hash>
```

**Status:** nginx extensions nie zainstalowane jeszcze — wymaga:
```bash
cp nginx/upstream-wkd.conf /opt/zextras/conf/nginx/extensions/
cp nginx/backend-wkd.conf  /opt/zextras/conf/nginx/extensions/
chown zextras:zextras /opt/zextras/conf/nginx/extensions/*-wkd.conf
nginx -s reload
```

---

## Pliki operacyjne

| Plik | Opis |
|------|------|
| `install.sh` | Instalacja na nowym serwerze |
| `encedo-wkd-nginx-inject.sh` | Konfiguracja nginx + certy (uruchom po install.sh) |
| `encedo-wkd.service` | Plik systemd |
| `nginx/upstream-wkd.conf` | Do `/opt/zextras/conf/nginx/extensions/` |
| `nginx/backend-wkd.conf` | Do `/opt/zextras/conf/nginx/extensions/` |

## Ponowne wdrożenie (po upgrade Carbonio / nowa domena)

```bash
sudo ./encedo-wkd-nginx-inject.sh
```

Skrypt automatycznie:
1. Pobiera domeny z Carbonio (`zmprov gad`)
2. Sprawdza DNS CNAME dla `openpgpkey.*`
3. Generuje certyfikaty Let's Encrypt (jeśli brak)
4. Wykrywa IP serwera z `nginx.conf.web.https.default`
5. Generuje nginx config + przeładowuje
6. Generuje `config.json`

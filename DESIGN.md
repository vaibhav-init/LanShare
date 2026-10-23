# lanshare — Design Decisions

Phone → laptop file sharing over the browser. QR code to open, 4-digit pairing
code to unlock uploads, animated progress. No apps to install on the phone.

## Core decisions

| Decision | Choice | Why |
|---|---|---|
| Language | Pure C, raw POSIX sockets | Learning goal: HTTP + sockets from scratch; no frameworks, no deps |
| Scope of transfer | **Upload only (phone → laptop)** | Downloads/listing dropped for simplicity — user explicitly cut it |
| Phone side | Browser only, zero installs | The whole point of the tool |
| Server footprint | ~5 C files + Makefile + 1 inline HTML page | Smallest complete thing |
| Connection model | detached pthread per connection | PIN state shared in-process behind a mutex; no zombie reaping, no fd juggling |

## File layout (planned)

```
src/main.c    CLI, accept loop, fork per client
src/net.c     listen socket, LAN IP discovery (getifaddrs), client IP
src/http.c    request parsing (headers), routing, responses
src/fs.c      upload streaming (multipart), path safety, file save
scripts/      waybar module + toggle script (pidfile based)
```

## The upload page

- `GET /` → one HTML page: drag-drop box, upload button, animated progress bar
- Progress animation via XMLHttpRequest `progress` events — free from the browser, no libs
- `POST /upload` → server streams body to disk, responds "done"

## Pairing PIN (security model)

1. Server start → random 4-digit PIN from `/dev/urandom` (never `srand(time)`)
2. PIN printed under the QR **and embedded in the QR** as `http://<ip>:<port>/?pin=4271`
   - Scanning the QR = instant pairing (page reads `?pin=`, no typing)
   - Knowing only the URL = still locked (must ask the owner for the code)
3. Server validates PIN on **every** `POST /upload` → wrong = `403`
4. Brute-force throttle: 5 wrong attempts → reject for 30 s (10,000 combos is not guessable through a throttle)
5. Page stores PIN in `localStorage` so re-uploads don't re-pair

PIN threat model: separates "scanned the QR in person" from "knows the address".
On public tunnel URLs the PIN is **mandatory** (strangers can reach the URL).

## QR + waybar

- QR via `qrencode` CLI (optional dependency — plain URL printed if absent)
- Clicking the waybar button starts server + shows QR popup; second button state stops it (`kill $(cat pidfile)`)
- Wayland popup is the known fiddly part (eww/rofi/imv options)

## Networking modes

| Mode | Reach | How |
|---|---|---|
| LAN (default) | same WiFi | QR encodes LAN IP from getifaddrs |
| `--tunnel` | any network | `ssh -R 80:localhost:8000 nokey@localhost.run` → public https URL goes in the QR |

Zero installs on laptop or phone; ssh is already on Arch. Free tunnel URLs are
temporary — acceptable for "send a file now", not for "always available".

## Rejected alternatives (and the reason each lost)

| Alternative | Why not |
|---|---|
| nginx as the server | Config, not code — no learning; uploads need WebDAV hacks; solves serving, not reachability |
| nginx on the laptop for cross-network | Wrong machine: NAT/CGNAT blocks inbound; no config file creates a route |
| LocalSend / Tailscale | Great daily tools, but the point here is building it in C; no-install constraint |
| `python -m http.server` | No upload page, not C, nothing learned |
| Whole-file-in-RAM upload parsing | 2 GB phone videos kill it → streaming parser required |
| fork() per connection | first version, replaced by threads so the PIN throttle could be shared and locked in-process |
| Thread pool | extra queue/condvar machinery nobody needed; thread-per-connection kept |

## Threading model (revisited — was fork)

- Original build: `fork()` per connection + `PinState` in `MAP_SHARED|MAP_ANONYMOUS`
  memory (children are separate address spaces, so the mmap was the only way to
  share the throttle).
- Now: **detached pthread per connection**. Threads share memory, so the mmap
  trick was deleted (plain static struct) — and the latent race it never solved
  got fixed properly: all PIN/throttle mutations happen under one mutex in fs.c.
- Verified: 4 simultaneous uploads saved byte-identical; parallel wrong-PIN
  requests stay race-free and lockout still fires after exactly 5.

Known limits (accepted):
- No cap on connection threads — N clients = N threads; a semaphore cap or a
  small pool is the upgrade if this ever runs on a hostile network.
- A slow client holds a thread up to 30 s (idle-read timeout) — cheap way to
  occupy threads; same fix as above.
- Log lines from threads can interleave mid-line (cosmetic).

## Never cut (hard requirements)

- Path sanitization at the trust boundary (reject `..`, decode `%XX`, no escapes from the shared root)
- Streaming multipart parser: rolling lookahead boundary scanner — never buffer the whole body in RAM (cap `MAX_BODY` as backstop)
- PIN check + throttle on every upload
- Error handling on partial writes / disconnects mid-upload (no truncated "successful" files)

## Future (v2, out of scope for now)

Rendezvous relay in C on a VPS ("mini-ngrok"): laptop dials out and registers a
session; phone hits the VPS URL; relay multiplexes phone bytes over the laptop's
outbound tunnel. v1 HTTP code stays untouched (laptop side becomes a byte pipe).
nginx's only role in that world: TLS termination **on the VPS**, in front of the relay.

## Known limits (accepted for v1)

- Free tunnel URLs are temporary and rotate per session
- Anyone on the LAN with URL + PIN can upload to you
- QR needs `qrencode` installed (pacman -S qrencode) — otherwise plain URL only
- LAN mode is plaintext HTTP (fine for home; tunnel mode gives https for free)

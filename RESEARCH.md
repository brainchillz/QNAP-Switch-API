# Reverse-engineering the QNAP QSW-M5216-1T API

How an unofficial, undocumented switch API was discovered, understood, and
turned into a scriptable tool (`qsw.py`). This is the "why it works" companion
to [`README.md`](./README.md) (how to use it) and [`API.md`](./API.md) (the raw
endpoint list).

- [1. The problem](#1-the-problem)
- [2. Reconnaissance](#2-reconnaissance)
- [3. Finding the API in the web UI](#3-finding-the-api-in-the-web-ui)
- [4. Authentication](#4-authentication)
- [5. API conventions](#5-api-conventions)
- [6. Data models](#6-data-models)
- [7. The gotchas (and how they were found)](#7-the-gotchas-and-how-they-were-found)
- [8. From API to tool](#8-from-api-to-tool)
- [9. Methodology notes](#9-methodology-notes)

---

## 1. The problem

The QSW-M5216-1T is a 16×25GbE + 1×10GbE managed switch running QNAP's "QSS"
firmware. QNAP publishes **no API documentation** for it — the only supported
management path is the QSS web GUI. The goal: drive VLANs, ports, etc.
programmatically anyway.

The web UI, however, has to talk to the switch *somehow*. If it's a browser
app hitting an HTTP backend, that backend is an API we can call directly. That
hunch is the whole basis of this project, and it turned out to be correct.

## 2. Reconnaissance

First, what's listening on the switch (`192.0.2.10`):

| Port | Result | Meaning |
|------|--------|---------|
| 80/tcp | open | HTTP web UI |
| 443/tcp | open | HTTPS web UI |
| 161/udp | open | SNMP (monitoring only; VLAN writes not supported there) |
| 22/tcp | closed | no SSH |
| 23/tcp | refused | no Telnet |

No CLI access (SSH/Telnet), so the switch **can't** be driven like a Cisco/
Arista box. SNMP is read-oriented. That leaves the web UI's backend as the only
real avenue — which is what we want.

Fetching `GET /` returns a tiny HTML shell:

```html
<div id=app></div>
<script src=/static/js/manifest.….js></script>
<script src=/static/js/vendor.….js></script>
<script src=/static/js/app.….js></script>
```

This is a **single-page app** (Vue + webpack). An empty `<div id=app>` filled
by JavaScript means all the real logic — including every backend call — lives
in those bundles. So the plan: download the bundles and read them.

## 3. Finding the API in the web UI

The app bundle (`app.….js`) is minified but not obfuscated. Searching it for
URL-ish strings immediately surfaced the API base:

```
"/api/v1"
```

The endpoints themselves are built dynamically — the code uses an axios
instance (`Hi`) and a base constant (`Fi = "/api/v1"`), so calls look like
`Hi.get(Fi + "/vlan")`. A regex over the bundle for that pattern enumerated the
**entire API surface** — 126 endpoints:

```python
re.finditer(r'Hi\.(get|post|put|delete)\(Fi\+"([^"]+)"', js)
```

That single regex produced [`API.md`](./API.md). The service functions are
conveniently named (`getVlan`, `setVlan`, `delVlan`, `addLagStatus`, …), so
each endpoint's purpose was readable straight from the code.

## 4. Authentication

The login flow, read directly from the bundle's `postLogin` action:

```
POST /api/v1/users/login
Content-Type: application/json
{"username": "<user>", "password": "<encoded>"}
```

**The password encoding.** The UI builds the payload as
`pwd = _.ezEncode(this.password)`. `ezEncode` looked like a custom cipher, but
extracting its implementation revealed it uses the alphabet:

```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

…which is **standard Base64**. So `ezEncode` is a hand-rolled Base64 encoder,
and the password is simply Base64 of the plaintext. Verified from the shell:

```bash
B64=$(printf '%s' 'yourpassword' | base64)
curl -s -X POST http://192.0.2.10/api/v1/users/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"<user>\",\"password\":\"$B64\"}"
```

Response:

```json
{"error_code": 200, "error_message": "OK", "result": "eyJhbGciOiJSUzI1NiI..."}
```

**The token.** `result` is a **JWT** (RS256). Decoding its payload:

```json
{"Ip": "192.0.2.20", "Privilege": 15, "Proto": "HTTP/1.1",
 "UserName": "<user>", "iat": 1783229194}
```

Note there's no `exp` claim — the session is tracked server-side (the UI also
sets a `QSW_SID` cookie), so tokens go stale on their own timeline. Every
subsequent request authenticates with:

```
Authorization: Bearer <JWT>
```

Related auth endpoints: `GET /users/verification` (validate a token),
`POST /users/exit` (logout). If any call returns **401**, the token is stale —
re-login and retry. The tool caches the token (`~/.cache/qsw/<host>.token`) for
~20 minutes and transparently re-logs-in on a 401.

## 5. API conventions

**Response envelope.** Almost every endpoint returns:

```json
{"error_code": 200, "error_message": "OK", "result": <payload>}
```

`error_code == 200` means success; anything else is an error whose message is in
`error_message`. The tool unwraps `result` and raises on non-200.

**Collections use `{key, val}`.** List endpoints return an array of
`{"key": <id>, "val": <object>}`. `GET /vlan?key=<id>` filters to one.

**Writes are inconsistent** — and this is the single most important thing to
know about this API. Different endpoints expect *different* body shapes, and
sending the wrong one **silently no-ops** (returns 200 with `result: null` while
changing nothing). The shapes, all confirmed against the running switch:

| Endpoint | Method | Body shape |
|----------|--------|-----------|
| `/vlan` | POST/PUT | `{"data": [{"key": "<id>", "val": [...]}]}` |
| `/vlan` | DELETE | `{"idx": ["<id>", ...]}` |
| `/portlist` | PUT | `[{"idx": "<port>", "data": {...}}]`  ← **not** `key`/`val`! |
| `/lacp/group` | POST | `{"idx": "<grp>", "data": {"PortMembers":[...], "AggrMode":n}}` |
| `/lacp/group` | DELETE | `{"idx": ["<grp>", ...]}` |
| `/system/save` | PUT | `{}` (empty — persists running→startup) |
| `/system/config` | GET | binary tar blob (config backup) |
| `/system/config` | POST | `multipart/form-data`, file field **`conf`** |

The reliable way to get a write shape right is to read the exact payload the UI
builds for that action, rather than guessing from the GET shape.

## 6. Data models

**VLAN** (`GET /vlan`) — a pure 802.1Q membership table:

```json
{"key": "100", "val": [{"Port": "1", "Tagged": true}, {"Port": "5", "Tagged": false}]}
```

- A port in `val` is a member; absent = not a member.
- `Tagged: true` = tagged/trunk; `false` = untagged/access.
- There is **no PVID, no port "mode", and no VLAN name** field (see §7).
- Interfaces run `1-16` (SFP28 25G), `17` (10GbE RJ45), `18-25` (LAG groups).

**Port config** (`GET /ports`) — one object per interface (all 25):

```json
{"key": "1", "val": {"AutoMode": true, "Shutdown": false, "Speed": "twentyfiveGB",
  "MTU": 9016, "FC": false, "FEC": "auto", "Alias": "Slot0/1", ...}}
```

Written back via `PUT /portlist` in the `{idx, data}` shape. Speed values on
write take an `_fdx` suffix and set `AutoMode` (`autoNegMode`, `twentyfiveGB_fdx`,
`tenGB_fdx`, `oneGB_fdx`).

**MAC forwarding table** (`GET /mac/fdb/status`) — note the composite key:

```json
{"key": ["1", "A8:9C:6C:88:10:2D"], "val": {"Port": "11", "Dynamic": true}}
```

`key = [vlan_id, mac]`. `GET /mac` gives the aging time (`{"AgeTime": 300}`).

**LAG** (`GET /lacp/group`) — 8 groups:

```json
{"key": "1", "val": {"PortMembers": ["15", "16"], "AggrMode": 1}}
```

`AggrMode`: **1 = LACP active, 2 = static, 3 = disabled**. `GET /lacp/info`
gives `StartIndex: 17`, so **group N is interface 17+N** (group 1 → interface
18). That's how a bond gets its own VLAN-taggable interface.

Other read models used by the tool: `GET /system/sensor` (temp + fan RPM),
`GET /lldp/neighbors/status` (neighbor chassis/port per local port).

## 7. The gotchas (and how they were found)

These are the non-obvious behaviors that only surfaced through live testing.
They're the reason the tool behaves the way it does.

1. **Wrong write-body shape silently succeeds.** The first MTU-write attempts
   returned `200 / result: null` but changed nothing, because `/portlist`
   wants `{idx, data}` while `GET /ports` returns `{key, val}`. Found by reading
   the UI's exact payload builder: `r.push({idx: t.key, data: t.val})`. Lesson:
   a 200 is not proof a write took effect — always read back.

2. **VLAN names are unsupported and silently dropped.** Sending `name`/
   `description` fields on a VLAN create returns 200, but reading it back shows
   only `{key, val}`. The QSS VLAN UI has no name field either. Conclusion: the
   firmware has no VLAN-name concept, so the tool stores labels **locally**
   (`vlan-names.json`) and overlays them on display.

3. **MTU is hidden but fully functional.** `MTU` isn't in the QSS web UI at all,
   yet it's a real per-interface field settable via `/portlist`. Empirical
   boundary testing (writing 100 / 1500 / 9216 / 12288 / 16000 and reading
   back) showed the switch **clamps to 10000 max**; default is 9016 (jumbo).

4. **Membership is explicit — there is no "trunk mode".** Because there's no
   PVID or port mode, a "trunk" is literally "tagged member of every VLAN," and
   a VLAN created *later* won't include a port until you re-add it. The tool's
   `trunk`/`access` commands are therefore read-modify-write loops across all
   VLANs, with `--native` to leave one VLAN untagged.

5. **Bonding resets VLAN config.** Creating a LAG wipes the member ports' VLAN
   membership (confirmed: ports 15/16 went to `{}` after bonding). So you bond
   first, then assign VLANs to the LAG *interface* (18-25), never the members.

6. **Config lives in "running" until saved.** Writes take effect immediately but
   only persist across reboot after `PUT /system/save` (empty body). The tool
   exposes this as `save` and as a `--save` flag on write commands.

## 8. From API to tool

`qsw.py` is a single Python file (stdlib + `requests` + `pyyaml`) with two
layers.

**The `QSW` client class** handles everything transport-related:

- credential loading (args → env → `../qnap-creds`);
- `login()` with Base64 password + JWT caching to disk;
- a generic `request(method, path, data)` that attaches the bearer token,
  unwraps the `{error_code, result}` envelope, raises on non-200, and
  **auto-re-logs-in once on 401**;
- thin per-feature methods (`vlans`, `set_port_mtu`, `set_lag`, `mac_table`,
  `get_config_blob`, …) that just know each endpoint's quirky body shape.

**The CLI layer** (argparse subcommands) adds the ergonomics the raw API lacks:

- **Human intent → API model.** `trunk`/`access` express port roles the way an
  admin thinks and reconcile them into per-VLAN membership tables. `apply`
  extends this to a whole declarative `switch.yaml`.
- **Idempotency + dry-run.** Commands compute the diff first, only write what
  changed, and support `--dry-run`. Re-running is a no-op.
- **Safety.** `apply` auto-backs-up before writing; `restore` refuses without
  `--yes`; port speed changes warn about link bounce.
- **Local VLAN labels** paper over the firmware's missing VLAN names, and are
  accepted anywhere an id is (`access 5 servers`).
- **`raw METHOD path --data`** is an escape hatch to any of the 126 endpoints
  for anything without a dedicated command yet.

Design principle throughout: **the switch's own web UI is the reference
implementation.** When a write shape or field value was unclear, the answer was
always in how the UI built that exact request — not in guesswork.

## 9. Methodology notes

The workflow that made this tractable, reusable for any similar SPA-driven
appliance:

1. **Port scan** to find the management surface and rule out CLI paths.
2. **Identify the SPA** and download its JS bundles.
3. **Regex the bundle** for the API base, the request helper pattern, and named
   service functions — this maps the whole API without a single live call.
4. **Extract the auth flow** (login endpoint, payload encoding, token handling)
   from the login action, and reproduce it with `curl`.
5. **Confirm shapes live**, read-only first, then careful writes on unused
   resources (a spare/link-down port, a throwaway VLAN id) with immediate
   read-back and revert.
6. **Empirically probe** ranges/limits and watch for silent no-ops.
7. **Wrap** the confirmed behavior in a client + CLI, encoding every gotcha as
   code so nobody has to rediscover it.

Every write in this project was tested on link-down ports or throwaway VLAN ids
and reverted; the switch was returned to its exact original state after each
test.

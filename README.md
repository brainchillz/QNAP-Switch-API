# NetworkController — QNAP QSW managed-switch programmatic control

Script-driven management of QNAP **QSW** managed switches, without touching the
QSS web UI. The tool **auto-detects the API version** (via `GET /api/about`) and
adapts, so the same commands work across models: port types (SFP vs RJ45) and
the LAG offset are derived at runtime, not hardcoded.

## Supported switches

**Tested live** (both directions of every command exercised):

| Switch | API | Interfaces |
|--------|-----|------------|
| **QSW-M5216-1T** | **v1** | 16×SFP28 25G (1-16), 1×10G RJ45 (17), LAG 18-25 |
| **QSW-M3216R-8S8T** | **v2** | 8×10GBASE-T RJ45 (1-8), 8×SFP28 25G (9-16), LAG 17-24 |

**Likely compatible but untested** — the v2 firmware bundle is shared across a
whole family, so these should work via the same auto-detection (report back if
you try one): `QSW-M3212R-8S4T`, `QSW-M3224(P)-24T`, `QSW-M5218(P)-6F12T`,
`QSW-M7230(P)-2X4F24T`, `QSW-M7308R-4X`, `QSW-IM3216-8S8T`, and other QSS v1/v2
`QSW-M*` models. The tool never hardcodes a model — it reads the port layout
from the switch — so a new model mostly needs the endpoints it exposes to match.

> **v2 caveat:** on v2, per-port MTU, flow-control, and forced speed are not
> settable through `/portlist` (the switch silently drops them / 400s). The tool
> reads back after every port write and **errors loudly** rather than reporting a
> false success. VLANs, enable/disable, LAG, and all reads work fully. See below.

## How it works

The QSS web interface is a single-page app that talks to a private, undocumented
REST API. This project drives that same API directly. Reconnaissance findings:

- **Open ports:** HTTP 80, HTTPS 443, SNMP/UDP 161. No SSH/telnet.
- **Version:** `GET /api/about` returns `{"ApiVersion":"v1"|"v2", ...}` — this
  selects the base path (`/api/v1` or `/api/v2`). Both generations answer it.
- **Auth (identical on both):** `POST /api/<ver>/users/login` with
  `{"username","password"}` where the password is **standard base64** of the
  plaintext. Returns a JWT; send it as `Authorization: Bearer <jwt>`.
- **Surface:** v1 has 126 endpoints; v2 has 212 (adds L3 routing, 802.1x, ARP
  inspection, air-gap, IP source guard, PFC, PTP, RADIUS, …). See
  [`API.md`](./API.md) (v1) and [`API-v2.md`](./API-v2.md) (v2).
- **VLAN model:** `{"key":"<vlan-id>", "val":[{"Port":"<n>","Tagged":<bool>}]}`.
  Ports in `val` are members (Tagged=true → trunk/tagged, false →
  access/untagged); ports absent are non-members. **v2 adds a native `name`
  field** on each VLAN (v1 has none — see `name` labels below).
- **Persistence:** writes apply immediately to the running config. Run `save`
  (or pass `--save`) to persist running→startup so they survive a reboot.

### v1 vs v2 differences the tool handles for you

- **VLAN edits** use `PUT /vlan` on v1 but `PUT /vlan/align` on v2 (plain
  `PUT /vlan` 400s there). Create/delete are `/vlan` on both.
- **Port writes** (`/portlist`): v2 requires `MediaType` capitalized and an
  `?autosave=true` query, or the write is silently ignored.
- **Flow-control** is a bool on v1, an `"enable"/"disable"` string on v2.
- **Known v2 limitations:** the switch accepts port **enable/disable** via
  `/portlist` but **silently rejects per-port MTU and flow-control**, and
  **400s on forced speed**. The tool now **reads back after every port write and
  errors loudly** if the switch didn't apply it (no more silent no-ops). VLAN
  operations, enable/disable, LAG, and all reads work fully on both.

## Setup

Needs Python 3 with `requests` (already installed here). Credentials are read
from `../qnap-creds` by default, or `QSW_USER`/`QSW_PASS` env vars.

```bash
chmod +x qsw.py
```

## Usage

```bash
# Read
./qsw.py vlans                 # list all VLANs with tagged/untagged ports
./qsw.py vlan 100              # show one VLAN
./qsw.py ports                 # port link/speed table
./qsw.py vlans --json          # raw JSON (works on most read commands)

# Create / modify VLANs
./qsw.py add 250 --tagged 1-4,17 --untagged 5,6   # create VLAN 250
./qsw.py set 250 --tagged 1-8                      # REPLACE 250's membership
./qsw.py del 250 260                               # delete VLAN(s)
./qsw.py add 250 --tagged 1-4 --save              # create + persist to startup

# Trunk a port across ALL VLANs (full 802.1Q trunk)
./qsw.py trunk 17                      # port 17 -> tagged member of every VLAN
./qsw.py trunk 17 --native 1           # ...but VLAN 1 carried untagged (native)
./qsw.py trunk 20 --dry-run            # preview changes (LAG 3), touch nothing
./qsw.py trunk 17 --except 30,700      # trunk all VLANs except 30 and 700
./qsw.py trunk 17 --native 1 --save    # trunk + persist

# Access port: untagged on ONE VLAN, removed from all others (inverse of trunk)
./qsw.py access 5 300                   # port 5 -> untagged member of VLAN 300 only
./qsw.py access 5 300 --dry-run         # preview
./qsw.py access 5 300 --save            # + persist

# MTU (max frame size) — per interface (physical + LAG)
./qsw.py mtu 17                         # show port 17's MTU
./qsw.py mtu 1-16                       # show MTU for a range
./qsw.py mtu 17 1500                    # set port 17 MTU to 1500
./qsw.py mtu 1-16 9016 --save           # set + persist (9016 = default jumbo)

# VLAN name labels (stored LOCALLY — the switch has no VLAN names)
./qsw.py name 100 servers               # label VLAN 100 "servers"
./qsw.py name --list                    # list labels
./qsw.py vlans                          # labels show in the table
./qsw.py access 5 servers               # use a label anywhere an id is accepted

# Port control (enable/disable, speed, flow-control)
./qsw.py port 3                         # show port 3 state
./qsw.py port 5 --disable               # shut a port down
./qsw.py port 5 --enable                # bring it back up
./qsw.py port 17 --speed 10g            # force speed (auto|1g|10g|25g)
./qsw.py port 3 --flow-control on --save

# Visibility & health
./qsw.py ports                          # link/speed/MTU table
./qsw.py neighbors                      # LLDP: what's plugged into each port
./qsw.py health                         # switch temperature + fan RPM
./qsw.py macs                           # learned MAC table (MAC / VLAN / port)
./qsw.py macs --port 3                  # only MACs seen on port 3
./qsw.py macs --vlan servers            # by VLAN (id or label)
./qsw.py macs --mac 00:50:56            # by MAC substring (OUI lookup, etc.)
./qsw.py find a89c6c                    # which port/VLAN is this host on? (any format)

# Link aggregation (bonding)
./qsw.py lag                            # list all 8 LAG groups
./qsw.py lag set 1 15,16                # bond ports 15+16 as group 1 (LACP)
./qsw.py lag set 1 15,16 --mode static  # static (non-LACP) bond
./qsw.py lag del 1                      # remove group 1

# Declarative config — reconcile the whole switch to a YAML file
./qsw.py apply switch.yaml --dry-run    # preview the plan, change nothing
./qsw.py apply switch.yaml              # apply (auto-backs-up first)
./qsw.py apply switch.yaml --save       # apply + persist to startup

# Config backup / restore
./qsw.py backup                         # -> qsw-backup-<host>-<timestamp>.bin
./qsw.py backup myswitch.bin            # to a named file
./qsw.py restore myswitch.bin --yes     # DESTRUCTIVE: replaces config, reboots

# Escape hatch — hit ANY of the 126 endpoints directly
./qsw.py raw GET /ports/statistics
./qsw.py raw PUT /vlan --data '{"data":[{"key":"99","val":[{"Port":"1","Tagged":true}]}]}'
./qsw.py save                                      # persist running->startup
```

Notes:
- `set` replaces the *entire* member list for a VLAN (mirrors the web UI). To
  tweak, read the VLAN first, adjust, then `set` the full desired list.
- `trunk` is a read-modify-write across every VLAN (one PUT per VLAN that needs
  changing; idempotent). This switch has **no native port "trunk mode" or PVID**
  — membership is a pure 802.1Q table — so a trunk is literally "tagged on all
  VLANs." Consequence: a VLAN you create *later* won't include the port until
  you re-run `trunk` (or add the port when creating it). Use `--native <vid>`
  to leave one VLAN untagged so untagged ingress on the port has a home.
- `access <port> <vid>` is the inverse of `trunk`: untagged member of exactly
  one VLAN, removed from every other VLAN. Idempotent; the VLAN must exist.
- `mtu` is **per-interface** (physical ports 1-17 and LAG groups 18-25), not
  per-VLAN — MTU isn't a VLAN property on this L2 switch. Default is 9016
  (jumbo); the switch clamps values above 10000. Not exposed in the QSS web
  UI at all, but fully settable through the API.
- `name` labels are **local only** (stored in `vlan-names.json`, path override
  `QSW_NAMES`). The switch firmware has no VLAN-name field — verified by writing
  one and watching it get dropped. Labels are accepted anywhere a VLAN id is
  (e.g. `vlan storage`, `access 5 servers`, `trunk 17 --native mgmt`).
- `port --speed` writes the switch's forced-speed value (`auto` re-enables
  autoneg). Speed changes can bounce a live link — use `--dry-run` first.
- `backup` downloads the full config as a tar blob; `restore` re-uploads it and
  the switch **reboots**. `restore` refuses to run without `--yes`. Both use
  endpoints the web UI's System > Backup/Restore page uses.
- `lag` group N shows up as **interface 17+N** (group 1 = interface 18) in
  `ports`/`vlans` — give that interface its VLAN role, not the member ports.
  Members must be ≥2 SFP28 ports (1-16). Bonding **resets the member ports'
  VLAN config**, so bond first, then assign VLANs to the LAG interface.
- `apply` reconciles the switch to a declarative `switch.yaml` (see
  `switch.example.yaml`). It's idempotent, only changes what differs, never
  deletes VLANs or touches unlisted ports, and **auto-backs-up** before writing
  (unless `--dry-run` or `--no-backup`). Port roles are expressed the way you
  think about them (`mode: access/trunk`) and reconciled into the switch's
  per-VLAN membership tables for you.
- `--host` / `--scheme` flags override the target (defaults:
  `192.0.2.10`, `http`). Point `--host 192.0.2.11` at the M3216R (v2);
  the API version is detected automatically.
- The JWT (and detected API version) is cached under `~/.cache/qsw/` per host
  for ~20 min and auto-refreshed on 401.

## Extending

`qsw.py` exposes a `QSW` class with a generic `request(method, path, data)`
method and cached auth. Any endpoint in [`API.md`](./API.md) is a one-liner —
e.g. add `lacp`, `acl`, or `poe` subcommands the same way the VLAN commands are
built. The `raw` CLI command already reaches all of them for ad-hoc use.

## Files

- `qsw.py` — the client library + CLI (auto-detects API v1/v2).
- `RESEARCH.md` — how the API/auth were reverse-engineered (§10 covers API v2).
- `API.md` — v1 endpoint map (QSW-M5216-1T, 126 endpoints).
- `API-v2.md` — v2 endpoint map (QSW-M3216R-8S8T, 212 endpoints).
- `switch.example.yaml` — annotated declarative config for `apply`.

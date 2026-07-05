#!/usr/bin/env python3
"""
qsw.py — programmatic control of a QNAP QSW-M series managed switch (QSS).

The QSS web UI is a single-page app that drives a private REST API at
`/api/v1`. This tool speaks that same API directly, so anything the web UI
can do can be scripted. Focus is VLANs, but a `raw` escape hatch reaches all
126 endpoints.

Auth flow (reverse-engineered from the UI bundle):
  POST /api/v1/users/login  {"username": <user>, "password": base64(<pass>)}
    -> {"error_code":200, "result": "<JWT>"}
  Every other call sends:   Authorization: Bearer <JWT>

VLAN data model:
  A VLAN is {"key": "<vlan-id>", "val": [{"Port": "<n>", "Tagged": <bool>}...]}
  - Ports present in `val` are members; ports absent are NOT members.
  - Tagged=true  -> port carries this VLAN tagged (trunk).
  - Tagged=false -> port is an untagged/access member of this VLAN.
  Ports are "1".."16" (SFP28) plus "17" (the 10GbE RJ45).

Changes take effect immediately (running config). Run `save` (or pass
--save on a write) to persist running->startup so they survive a reboot.
"""

import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path

import requests
import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HOST = os.environ.get("QSW_HOST", "192.0.2.10")
DEFAULT_SCHEME = os.environ.get("QSW_SCHEME", "http")  # 80 and 443 both open
CREDS_FILE = os.environ.get("QSW_CREDS", str(Path(__file__).resolve().parent.parent / "qnap-creds"))
TOKEN_DIR = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "qsw"
NAMES_FILE = os.environ.get("QSW_NAMES", str(Path(__file__).resolve().parent / "vlan-names.json"))
PHYS_PORTS = 17   # 1-16 = SFP28 25G, 17 = 10GbE RJ45
MAX_IFACE = 25    # 18-25 = LAG (link-aggregation) groups, also VLAN-taggable
MTU_MIN, MTU_MAX = 68, 10000   # switch clamps MTU to <=10000; default 9016 (jumbo)

# Port speed keywords -> the value the /portlist API expects (25G SFP28 ports).
# The switch has NO VLAN-name support, so names are kept locally (see NAMES_FILE).
SPEED_MAP = {"auto": "autoNegMode", "25g": "twentyfiveGB_fdx",
             "10g": "tenGB_fdx", "1g": "oneGB_fdx"}


class QSWError(Exception):
    pass


class QSW:
    def __init__(self, host=DEFAULT_HOST, scheme=DEFAULT_SCHEME, user=None, password=None,
                 verify=False, timeout=15):
        self.base = f"{scheme}://{host}/api/v1"
        self.host = host
        self.user = user
        self.password = password
        self.verify = verify
        self.timeout = timeout
        self.token = None
        self.s = requests.Session()
        self._token_path = TOKEN_DIR / f"{host}.token"

    # ---- auth -------------------------------------------------------------
    def _load_creds(self):
        if self.user and self.password:
            return
        u = os.environ.get("QSW_USER")
        p = os.environ.get("QSW_PASS")
        if u and p:
            self.user, self.password = u, p
            return
        if os.path.exists(CREDS_FILE):
            creds = {}
            for line in Path(CREDS_FILE).read_text().splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    creds[k.strip().lower()] = v.strip()
            self.user = self.user or creds.get("username")
            self.password = self.password or creds.get("password")
        if not (self.user and self.password):
            raise QSWError(f"No credentials (checked args, QSW_USER/QSW_PASS env, {CREDS_FILE})")

    def _cached_token(self):
        try:
            data = json.loads(self._token_path.read_text())
            # tokens are session-scoped; treat as valid for 20 min then refresh
            if time.time() - data["ts"] < 1200:
                return data["token"]
        except Exception:
            pass
        return None

    def _store_token(self, token):
        try:
            TOKEN_DIR.mkdir(parents=True, exist_ok=True)
            self._token_path.write_text(json.dumps({"token": token, "ts": time.time()}))
            os.chmod(self._token_path, 0o600)
        except Exception:
            pass

    def login(self, force=False):
        if not force:
            tok = self._cached_token()
            if tok:
                self.token = tok
                return tok
        self._load_creds()
        pw = base64.b64encode(self.password.encode()).decode()
        r = self.s.post(f"{self.base}/users/login",
                        json={"username": self.user, "password": pw},
                        verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        body = r.json()
        if body.get("error_code") != 200:
            raise QSWError(f"Login failed: {body.get('error_message')} ({body.get('error_code')})")
        self.token = body["result"]
        self._store_token(self.token)
        return self.token

    # ---- core request -----------------------------------------------------
    def request(self, method, path, data=None, params=None, _retry=True):
        if not self.token:
            self.login()
        url = self.base + path
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        r = self.s.request(method, url, headers=headers,
                           data=json.dumps(data) if data is not None else None,
                           params=params, verify=self.verify, timeout=self.timeout)
        if r.status_code == 401 and _retry:
            self.login(force=True)
            return self.request(method, path, data=data, params=params, _retry=False)
        r.raise_for_status()
        if not r.content:
            return None
        try:
            body = r.json()
        except ValueError:
            return r.text
        if isinstance(body, dict) and body.get("error_code") not in (None, 200):
            raise QSWError(f"{method} {path}: {body.get('error_message')} ({body.get('error_code')})")
        return body.get("result") if isinstance(body, dict) and "result" in body else body

    # ---- VLAN helpers -----------------------------------------------------
    def vlans(self):
        return self.request("GET", "/vlan")

    def vlan_ids(self):
        return self.request("GET", "/vlan/indexs")["idx"]

    def vlan(self, vid):
        res = self.request("GET", "/vlan", params={"key": str(vid)})
        return res[0] if res else None

    def vlan_write(self, vid, tagged=None, untagged=None, action="add"):
        val = [{"Port": str(p), "Tagged": True} for p in (tagged or [])]
        val += [{"Port": str(p), "Tagged": False} for p in (untagged or [])]
        method = "POST" if action == "add" else "PUT"
        return self.request(method, "/vlan", data={"data": [{"key": str(vid), "val": val}]})

    def vlan_delete(self, vids):
        return self.request("DELETE", "/vlan", data={"idx": [str(v) for v in vids]})

    def set_trunk(self, port, native=None, exclude=(), dry_run=False):
        """Make `port` a tagged member of every VLAN (a full 802.1Q trunk).

        If `native` (a VLAN id) is given, that VLAN carries the port untagged
        instead of tagged, giving untagged ingress on the port a home.
        `exclude` is a set of VLAN ids to leave untouched. Read-modify-write,
        one PUT per VLAN that actually needs to change. Returns the list of
        (vlan_id, tagged) changes made.
        """
        port = str(port)
        exclude = {str(e) for e in exclude}
        native = None if native is None else str(native)
        changes = []
        for v in self.vlans():
            vid = v["key"]
            if vid in exclude:
                continue
            want_tagged = vid != native
            cur = next((m for m in v["val"] if str(m["Port"]) == port), None)
            if cur is not None and bool(cur["Tagged"]) == want_tagged:
                continue  # already correct
            new_val = [m for m in v["val"] if str(m["Port"]) != port]
            new_val.append({"Port": port, "Tagged": want_tagged})
            changes.append((vid, want_tagged))
            if not dry_run:
                self.request("PUT", "/vlan", data={"data": [{"key": vid, "val": new_val}]})
        return changes

    def set_access(self, port, vid, dry_run=False):
        """Make `port` an untagged access member of exactly VLAN `vid` and
        remove it from every other VLAN. Inverse of `set_trunk`. Read-modify-
        write, one PUT per VLAN that changes. Returns a list of
        (vlan_id, action) where action is 'access' or 'removed'.
        """
        port = str(port)
        vid = str(vid)
        if vid not in self.vlan_ids():
            raise QSWError(f"VLAN {vid} does not exist (create it first)")
        changes = []
        for v in self.vlans():
            k = v["key"]
            cur = next((m for m in v["val"] if str(m["Port"]) == port), None)
            if k == vid:
                if cur is not None and bool(cur["Tagged"]) is False:
                    continue  # already untagged member
                new_val = [m for m in v["val"] if str(m["Port"]) != port]
                new_val.append({"Port": port, "Tagged": False})
                action = "access"
            else:
                if cur is None:
                    continue  # already not a member
                new_val = [m for m in v["val"] if str(m["Port"]) != port]
                action = "removed"
            changes.append((k, action))
            if not dry_run:
                self.request("PUT", "/vlan", data={"data": [{"key": k, "val": new_val}]})
        return changes

    def ports_status(self):
        return self.request("GET", "/ports/status")

    def ports_config(self):
        """Per-port config (Speed, MTU, Alias, ...) keyed by port number."""
        return {p["key"]: p["val"] for p in self.request("GET", "/ports")}

    def set_port_mtu(self, ports, mtu, dry_run=False):
        """Set MTU (max frame size) on one or more interfaces. MTU is a
        per-interface property (physical ports 1-17 and LAG groups 18-25);
        this L2 switch has no per-VLAN MTU. Read-modify-write; sends only
        changed ports in a single PUT. Returns (port, old_mtu, new_mtu) list.
        """
        mtu = int(mtu)
        cur = self.ports_config()
        payload, changes = [], []
        for p in ports:
            p = str(p)
            if p not in cur:
                raise QSWError(f"port {p} has no MTU (valid interfaces: 1-{MAX_IFACE})")
            old = int(cur[p]["MTU"])
            if old == mtu:
                continue
            val = dict(cur[p]); val["MTU"] = mtu
            payload.append({"idx": p, "data": val})
            changes.append((p, old, mtu))
        if payload and not dry_run:
            self.request("PUT", "/portlist", data=payload)
        return changes

    def set_port(self, ports, shutdown=None, fc=None, speed=None, dry_run=False):
        """Enable/disable, set flow-control, and/or set speed on interfaces.
        `speed` is a raw API value (see SPEED_MAP). Read-modify-write; only
        changed ports are sent. Returns list of (port, [change descriptions]).
        """
        cur = self.ports_config()
        payload, changes = [], []
        for p in ports:
            p = str(p)
            if p not in cur:
                raise QSWError(f"port {p} not found (valid interfaces: 1-{MAX_IFACE})")
            val = dict(cur[p]); ch = []
            if shutdown is not None and bool(val.get("Shutdown")) != shutdown:
                val["Shutdown"] = shutdown
                ch.append("disabled" if shutdown else "enabled")
            if fc is not None and bool(val.get("FC")) != fc:
                val["FC"] = fc
                ch.append(f"flow-control {'on' if fc else 'off'}")
            if speed is not None:
                val["Speed"] = speed
                val["AutoMode"] = speed == "autoNegMode"
                ch.append(f"speed {speed}")
            if ch:
                payload.append({"idx": p, "data": val})
                changes.append((p, ch))
        if payload and not dry_run:
            self.request("PUT", "/portlist", data=payload)
        return changes

    def lldp_neighbors(self):
        return self.request("GET", "/lldp/neighbors/status")

    def mac_table(self):
        """Learned MAC/forwarding table: list of {vlan, mac, port, dynamic}."""
        rows = []
        for e in self.request("GET", "/mac/fdb/status"):
            vlan, mac = e["key"]
            rows.append({"vlan": vlan, "mac": mac,
                         "port": e["val"]["Port"], "dynamic": e["val"].get("Dynamic", True)})
        return rows

    def mac_agetime(self):
        return self.request("GET", "/mac").get("AgeTime")

    # ---- LAG / link aggregation ------------------------------------------
    def lag_start(self):
        """Interface-index offset: LAG group N is interface lag_start()+N."""
        return self.request("GET", "/lacp/info").get("StartIndex", 17)

    def lag_groups(self):
        return self.request("GET", "/lacp/group")

    def set_lag(self, group, ports, mode=1):
        """Create/replace LAG group (1-8) with member ports. mode: 1=LACP
        active, 2=static. NOTE: bonding resets the member ports' VLAN config."""
        return self.request("POST", "/lacp/group",
                             data={"idx": str(group),
                                   "data": {"PortMembers": [str(p) for p in ports],
                                            "AggrMode": int(mode)}})

    def del_lag(self, groups):
        return self.request("DELETE", "/lacp/group",
                            data={"idx": [str(g) for g in groups]})

    def sensor(self):
        return self.request("GET", "/system/sensor")

    def get_config_blob(self, _retry=True):
        """Raw config backup (binary blob) from GET /system/config."""
        if not self.token:
            self.login()
        r = self.s.get(self.base + "/system/config",
                       headers={"Authorization": f"Bearer {self.token}"},
                       verify=self.verify, timeout=60)
        if r.status_code == 401 and _retry:
            self.login(force=True)
            return self.get_config_blob(_retry=False)
        r.raise_for_status()
        return r.content

    def restore_config(self, path, _retry=True):
        """Upload a config backup to POST /system/config (multipart, field
        'conf'). Destructive: replaces the whole config and reboots."""
        if not self.token:
            self.login()
        with open(path, "rb") as fh:
            files = {"conf": (os.path.basename(path), fh, "application/octet-stream")}
            r = self.s.post(self.base + "/system/config",
                            headers={"Authorization": f"Bearer {self.token}"},
                            files=files, verify=self.verify, timeout=120)
        if r.status_code == 401 and _retry:
            self.login(force=True)
            return self.restore_config(path, _retry=False)
        r.raise_for_status()
        return r.json() if r.content else None

    def save(self):
        return self.request("PUT", "/system/save", data={})


# ---- port list parsing ----------------------------------------------------
def parse_ports(spec):
    """'1,2,5-8,17' -> [1,2,5,6,7,8,17]"""
    if not spec:
        return []
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    for p in out:
        if not 1 <= p <= MAX_IFACE:
            raise QSWError(f"port {p} out of range 1-{MAX_IFACE} "
                           f"(1-{PHYS_PORTS} physical, 18-{MAX_IFACE} LAG groups)")
    return sorted(set(out))


def fmt_ports(nums):
    """[1,2,5,6,7,8] -> '1-2,5-8' for compact display"""
    nums = sorted(int(n) for n in nums)
    if not nums:
        return "-"
    ranges, start, prev = [], nums[0], nums[0]
    for n in nums[1:]:
        if n == prev + 1:
            prev = n
            continue
        ranges.append((start, prev)); start = prev = n
    ranges.append((start, prev))
    return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in ranges)


# ---- local VLAN name labels (the switch itself has NO VLAN names) ----------
def load_names():
    try:
        return json.loads(Path(NAMES_FILE).read_text())
    except Exception:
        return {}


def save_names(names):
    Path(NAMES_FILE).write_text(json.dumps(names, indent=2, sort_keys=True) + "\n")


def resolve_vid(token):
    """Accept either a numeric VLAN id or a local label; return the id string."""
    token = str(token)
    if token.isdigit():
        return token
    names = load_names()
    for vid, label in names.items():
        if label.lower() == token.lower():
            return vid
    raise QSWError(f"unknown VLAN name {token!r} (see `qsw.py name --list`)")


# ---- CLI commands ---------------------------------------------------------
def cmd_vlans(sw, args):
    data = sw.vlans()
    if args.json:
        print(json.dumps(data, indent=2)); return
    names = load_names()
    print(f"{'VLAN':>5}  {'Name':<12}  {'Tagged (trunk)':<22}  {'Untagged (access)':<22}")
    print("-" * 70)
    for v in sorted(data, key=lambda x: int(x["key"])):
        tagged = [m["Port"] for m in v["val"] if m["Tagged"]]
        untag = [m["Port"] for m in v["val"] if not m["Tagged"]]
        label = names.get(v["key"], "")
        print(f"{v['key']:>5}  {label:<12}  {fmt_ports(tagged):<22}  {fmt_ports(untag):<22}")


def cmd_vlan(sw, args):
    vid = resolve_vid(args.id)
    v = sw.vlan(vid)
    if v is None:
        raise QSWError(f"VLAN {vid} not found")
    if args.json:
        print(json.dumps(v, indent=2)); return
    tagged = [m["Port"] for m in v["val"] if m["Tagged"]]
    untag = [m["Port"] for m in v["val"] if not m["Tagged"]]
    label = load_names().get(vid)
    print(f"VLAN {v['key']}" + (f"  ({label})" if label else ""))
    print(f"  tagged   : {fmt_ports(tagged)}")
    print(f"  untagged : {fmt_ports(untag)}")


def _write(sw, args, action):
    vid = resolve_vid(args.id)
    tagged = parse_ports(args.tagged)
    untag = parse_ports(args.untagged)
    overlap = set(tagged) & set(untag)
    if overlap:
        raise QSWError(f"ports in both tagged and untagged: {sorted(overlap)}")
    sw.vlan_write(vid, tagged=tagged, untagged=untag, action=action)
    verb = "Added" if action == "add" else "Updated"
    print(f"{verb} VLAN {vid}: tagged={fmt_ports(tagged)} untagged={fmt_ports(untag)}")
    if args.save:
        sw.save(); print("Persisted to startup config.")


def cmd_add(sw, args):
    _write(sw, args, "add")


def cmd_set(sw, args):
    _write(sw, args, "edit")


def cmd_del(sw, args):
    ids = [resolve_vid(x) for x in args.ids]
    sw.vlan_delete(ids)
    print(f"Deleted VLAN(s): {', '.join(ids)}")
    # drop any local labels for deleted VLANs
    names = load_names()
    if any(i in names for i in ids):
        for i in ids:
            names.pop(i, None)
        save_names(names)
    if args.save:
        sw.save(); print("Persisted to startup config.")


def _one_port(spec):
    ports = parse_ports(spec)
    if len(ports) != 1:
        raise QSWError(f"expected a single port, got {spec!r}")
    return ports[0]


def cmd_trunk(sw, args):
    port = _one_port(args.port)
    native = resolve_vid(args.native) if args.native else None
    exclude = [resolve_vid(x) for x in args.exclude.split(",")] if args.exclude else []
    changes = sw.set_trunk(port, native=native, exclude=exclude, dry_run=args.dry_run)
    prefix = "[dry-run] would set" if args.dry_run else "Set"
    if not changes:
        print(f"Port {port} is already a full trunk; nothing to change.")
    else:
        tagged = fmt_ports(v for v, t in changes if t)
        untag = fmt_ports(v for v, t in changes if not t)
        print(f"{prefix} port {port} trunk across {len(changes)} VLAN(s): "
              f"tagged=[{tagged}]" + (f" untagged=[{untag}]" if untag != '-' else ""))
    print("Note: membership is explicit — VLANs you create *later* will NOT "
          "include this port until you re-run trunk or add it.")
    if args.save and changes and not args.dry_run:
        sw.save(); print("Persisted to startup config.")


def cmd_access(sw, args):
    port = _one_port(args.port)
    vid = resolve_vid(args.vlan)
    changes = sw.set_access(port, vid, dry_run=args.dry_run)
    prefix = "[dry-run] would make" if args.dry_run else "Made"
    if not changes:
        print(f"Port {port} is already an access port on VLAN {vid}; nothing to change.")
    else:
        removed = fmt_ports(v for v, a in changes if a == "removed")
        print(f"{prefix} port {port} an untagged access member of VLAN {vid}"
              + (f"; removed from VLAN(s) [{removed}]" if removed != '-' else ""))
    if args.save and changes and not args.dry_run:
        sw.save(); print("Persisted to startup config.")


def cmd_mtu(sw, args):
    ports = parse_ports(args.ports)
    if args.value is None:  # show
        cur = sw.ports_config()
        for p in ports:
            if str(p) not in cur:
                print(f"port {p}: (no MTU — valid interfaces 1-{MAX_IFACE})")
            else:
                print(f"port {p}: MTU {cur[str(p)]['MTU']}")
        return
    mtu = int(args.value)
    if not MTU_MIN <= mtu <= MTU_MAX:
        raise QSWError(f"MTU {mtu} out of range {MTU_MIN}-{MTU_MAX}")
    changes = sw.set_port_mtu(ports, mtu, dry_run=args.dry_run)
    prefix = "[dry-run] would set" if args.dry_run else "Set"
    if not changes:
        print(f"MTU already {mtu} on port(s) {fmt_ports(ports)}; nothing to change.")
    else:
        for p, old, new in changes:
            print(f"{prefix} port {p} MTU {old} -> {new}")
    if args.save and changes and not args.dry_run:
        sw.save(); print("Persisted to startup config.")


def cmd_name(sw, args):
    names = load_names()
    if args.list or (args.vlan is None):
        if not names:
            print("No VLAN labels set. Add one:  qsw.py name 100 storage")
        for vid in sorted(names, key=int):
            print(f"{vid:>5}  {names[vid]}")
        return
    if not args.vlan.isdigit():
        raise QSWError("VLAN id must be numeric")
    if args.clear:
        names.pop(args.vlan, None); save_names(names)
        print(f"Cleared label for VLAN {args.vlan}"); return
    if args.label is None:
        print(f"{args.vlan}: {names.get(args.vlan, '(no label)')}"); return
    names[args.vlan] = args.label
    save_names(names)
    print(f"VLAN {args.vlan} labelled {args.label!r} (local only — the switch stores no VLAN names)")


def cmd_neighbors(sw, args):
    data = sw.lldp_neighbors()
    if args.json:
        print(json.dumps(data, indent=2)); return
    if not data:
        print("No LLDP neighbors discovered."); return
    print(f"{'Port':>4}  {'Neighbor chassis':<20}  {'Sys name':<16}  Port ID")
    print("-" * 64)
    for e in sorted(data, key=lambda x: int(x["key"])):
        v = e["val"]
        print(f"{e['key']:>4}  {v.get('ChassisId',''):<20}  "
              f"{(v.get('SystemName') or ''):<16}  {v.get('PortId','')}")


def cmd_port(sw, args):
    ports = parse_ports(args.ports)
    shutdown = None
    if args.enable:
        shutdown = False
    if args.disable:
        shutdown = True
    fc = {"on": True, "off": False}.get(args.flow_control)
    speed = SPEED_MAP[args.speed] if args.speed else None
    if shutdown is None and fc is None and speed is None:  # show
        cfg = sw.ports_config()
        for p in ports:
            v = cfg.get(str(p))
            if not v:
                print(f"port {p}: not found"); continue
            state = "disabled" if v.get("Shutdown") else "enabled"
            print(f"port {p}: {state}, speed={v.get('Speed')}, "
                  f"flow-control={'on' if v.get('FC') else 'off'}, MTU={v.get('MTU')}")
        return
    changes = sw.set_port(ports, shutdown=shutdown, fc=fc, speed=speed, dry_run=args.dry_run)
    prefix = "[dry-run] would set" if args.dry_run else "Set"
    if not changes:
        print(f"No change needed on port(s) {fmt_ports(ports)}.")
    for p, ch in changes:
        print(f"{prefix} port {p}: {', '.join(ch)}")
    if args.save and changes and not args.dry_run:
        sw.save(); print("Persisted to startup config.")


def cmd_backup(sw, args):
    blob = sw.get_config_blob()
    path = args.file or f"qsw-backup-{sw.host}-{time.strftime('%Y%m%d-%H%M%S')}.bin"
    Path(path).write_bytes(blob)
    print(f"Saved config backup: {path} ({len(blob)} bytes)")


def cmd_restore(sw, args):
    if not args.yes:
        raise QSWError("restore is destructive (replaces the whole config and "
                       "reboots the switch). Re-run with --yes to confirm.")
    if not os.path.exists(args.file):
        raise QSWError(f"file not found: {args.file}")
    print(f"Uploading {args.file} to {sw.host} ...")
    sw.restore_config(args.file)
    print("Restore accepted — the switch will apply the config and reboot.")


def cmd_macs(sw, args):
    rows = sw.mac_table()
    names = load_names()
    if args.port:
        want = set(str(p) for p in parse_ports(args.port))
        rows = [r for r in rows if r["port"] in want]
    if args.vlan:
        vid = resolve_vid(args.vlan)
        rows = [r for r in rows if r["vlan"] == vid]
    if args.mac:
        needle = _mac_norm(args.mac)
        rows = [r for r in rows if needle in _mac_norm(r["mac"])]
    rows.sort(key=lambda r: (int(r["port"]) if r["port"].isdigit() else 999,
                             int(r["vlan"]), r["mac"]))
    if args.json:
        print(json.dumps(rows, indent=2)); return
    print(f"{'MAC':<19}  {'VLAN':<14}  {'Port':>4}  Type")
    print("-" * 46)
    for r in rows:
        label = names.get(r["vlan"], "")
        vlan = f"{r['vlan']} {label}".strip()
        typ = "dynamic" if r["dynamic"] else "static"
        print(f"{r['mac']:<19}  {vlan:<14}  {r['port']:>4}  {typ}")
    print("-" * 46)
    print(f"{len(rows)} entries" + (f"  (aging {sw.mac_agetime()}s)" if not (args.port or args.vlan or args.mac) else ""))


def _mac_norm(s):
    return "".join(c for c in s.lower() if c in "0123456789abcdef")


def cmd_find(sw, args):
    needle = _mac_norm(args.mac)
    names = load_names()
    hits = [r for r in sw.mac_table() if needle in _mac_norm(r["mac"])]
    if not hits:
        print(f"No MAC matching {args.mac!r} in the forwarding table "
              f"(host may be idle — entries age out after {sw.mac_agetime()}s).")
        return
    for r in sorted(hits, key=lambda r: r["mac"]):
        label = names.get(r["vlan"], "")
        vlan = f"{r['vlan']} ({label})" if label else r["vlan"]
        print(f"{r['mac']}  ->  port {r['port']}, VLAN {vlan}")


AGGR_MODE = {"lacp": 1, "static": 2}
AGGR_NAME = {1: "LACP", 2: "static", 3: "disabled"}


def cmd_lag_list(sw, args):
    groups = sw.lag_groups()
    start = sw.lag_start()
    print(f"{'Group':>5}  {'Interface':>9}  {'Mode':<9}  Members")
    print("-" * 44)
    for g in sorted(groups, key=lambda x: int(x["key"])):
        v = g["val"]; members = v.get("PortMembers", [])
        mode = AGGR_NAME.get(v.get("AggrMode"), "?") if members else "-"
        iface = int(g["key"]) + start
        print(f"{g['key']:>5}  {iface:>9}  {mode:<9}  "
              f"{fmt_ports(members) if members else '(empty)'}")
    print(f"\nLAG group N appears as interface {start}+N in `ports`/`vlans` "
          f"(group 1 = {start+1}).")


def cmd_lag_set(sw, args):
    if not 1 <= args.group <= 8:
        raise QSWError("LAG group must be 1-8")
    ports = parse_ports(args.ports)
    if len(ports) < 2:
        raise QSWError("a LAG needs at least 2 member ports")
    if any(p > 16 for p in ports):
        raise QSWError("LAG members must be SFP28 ports 1-16 (10G port 17 and "
                       "LAG interfaces can't be members)")
    mode = AGGR_MODE[args.mode]
    print(f"WARNING: bonding resets the VLAN config of ports {fmt_ports(ports)}; "
          f"the group becomes interface {sw.lag_start()+args.group}, which you then "
          f"add to VLANs (e.g. `trunk {sw.lag_start()+args.group}`).")
    if args.dry_run:
        print(f"[dry-run] would set LAG {args.group} = ports {fmt_ports(ports)} ({args.mode})")
        return
    sw.set_lag(args.group, ports, mode=mode)
    print(f"LAG {args.group} set: ports {fmt_ports(ports)}, mode {args.mode} "
          f"(interface {sw.lag_start()+args.group})")
    if args.save:
        sw.save(); print("Persisted to startup config.")


def cmd_lag_del(sw, args):
    sw.del_lag([args.group])
    print(f"Deleted LAG group {args.group}")
    if args.save:
        sw.save(); print("Persisted to startup config.")


def cmd_health(sw, args):
    s = sw.sensor()
    if args.json:
        print(json.dumps(s, indent=2)); return
    print(f"Switch temp : {s['SwitchTemp']}°C  (max {s['MaxSwitchTemp']}°C)")
    print(f"Fan 1       : {s['Fan1Speed']} rpm")
    print(f"Fan 2       : {s['Fan2Speed']} rpm  (range {s['MinFanRpm']}-{s['MaxFanRpm']})")


def cmd_ports(sw, args):
    data = sw.ports_status()
    if args.json:
        print(json.dumps(data, indent=2)); return
    cfg = sw.ports_config()
    print(f"{'Port':>4}  {'Link':<6}  {'Speed':>7}  {'MTU':>6}  Name")
    print("-" * 42)
    for e in sorted(data, key=lambda x: int(x["key"])):
        p = int(e["key"]); v = e["val"]
        name = f"SFP28 {p}" if p <= 16 else ("10GbE" if p == 17 else f"LAG {p-17}")
        speed = f"{int(v['Speed'])//1000}G" if v.get("Speed") else "-"
        link = "up" if v.get("Link") else "down"
        mtu = cfg.get(str(p), {}).get("MTU", "-")
        print(f"{p:>4}  {link:<6}  {speed:>7}  {mtu:>6}  {name}")


def _describe_members(pm):
    tagged = [p for p, t in pm.items() if t]
    untag = [p for p, t in pm.items() if not t]
    return f"tagged {fmt_ports(tagged)}, untagged {fmt_ports(untag)}"


def _port_membership(pc, all_vids, resolve):
    """Desired {vid: 'tagged'|'untagged'} for a port's declared role, or None."""
    mode = pc.get("mode")
    if mode is None:
        return None
    desired = {}
    if mode == "access":
        if "vlan" not in pc:
            raise QSWError("access port needs a 'vlan'")
        desired[resolve(pc["vlan"])] = "untagged"
    elif mode == "trunk":
        tagged = pc.get("tagged", [])
        ids = list(all_vids) if tagged == "all" else [resolve(x) for x in tagged]
        for vid in ids:
            desired[vid] = "tagged"
        if pc.get("native") is not None:
            desired[resolve(pc["native"])] = "untagged"  # native overrides tagged
    else:
        raise QSWError(f"unknown port mode {mode!r} (use access|trunk)")
    return desired


def cmd_apply(sw, args):
    cfg = yaml.safe_load(Path(args.file).read_text()) or {}
    plan = []

    declared = {str(k): v for k, v in (cfg.get("vlans") or {}).items()}
    existing = sw.vlan_ids()
    all_vids = sorted(set(existing) | set(declared), key=int)

    # Resolver that understands labels declared in THIS file plus saved labels.
    name_to_id = {str(lbl).lower(): vid for vid, lbl in load_names().items()}
    name_to_id.update({str(lbl).lower(): vid for vid, lbl in declared.items() if lbl})

    def resolve(token):
        token = str(token)
        if token.isdigit():
            return token
        if token.lower() in name_to_id:
            return name_to_id[token.lower()]
        raise QSWError(f"unknown VLAN name {token!r} in {args.file}")

    # VLAN existence + local name labels
    names = load_names(); label_updates = {}
    for vid, label in declared.items():
        if label and names.get(vid) != str(label):
            label_updates[vid] = str(label); plan.append(f"label VLAN {vid} = {label!r}")
    to_create = [v for v in declared if v not in existing]
    for v in sorted(to_create, key=int):
        plan.append(f"create VLAN {v} (empty)")

    # Current membership tables: vid -> {port: tagged_bool}
    table = {v["key"]: {m["Port"]: m["Tagged"] for m in v["val"]} for v in sw.vlans()}
    for v in to_create:
        table[v] = {}
    original = {vid: dict(pm) for vid, pm in table.items()}

    # Reconcile per-port VLAN roles
    ports_cfg = {str(k): (v or {}) for k, v in (cfg.get("ports") or {}).items()}
    for pk, pc in ports_cfg.items():
        desired = _port_membership(pc, all_vids, resolve)
        if desired is None:
            continue
        for vid in table:  # strip this port from every VLAN first
            table[vid].pop(pk, None)
        for vid, kind in desired.items():
            table.setdefault(vid, {})[pk] = (kind == "tagged")
    changed_vids = [v for v in sorted(table, key=int) if table[v] != original.get(v, {})]
    for vid in changed_vids:
        plan.append(f"VLAN {vid}: {_describe_members(table[vid])}")

    # Port attributes (mtu / enabled / speed / flow_control)
    pcfg_now = sw.ports_config()
    attr_actions = []  # (port, kwargs, mtu)
    for pk, pc in ports_cfg.items():
        cur = pcfg_now.get(pk, {})
        kw, mtu = {}, None
        if "enabled" in pc and bool(cur.get("Shutdown")) == bool(pc["enabled"]):
            kw["shutdown"] = not pc["enabled"]
        if "flow_control" in pc:
            fc = bool(pc["flow_control"])
            if bool(cur.get("FC")) != fc:
                kw["fc"] = fc
        if pc.get("speed"):
            kw["speed"] = SPEED_MAP[pc["speed"]]
        if "mtu" in pc and int(cur.get("MTU", -1)) != int(pc["mtu"]):
            mtu = int(pc["mtu"])
        if kw:
            attr_actions.append((pk, kw)); plan.append(f"port {pk}: {', '.join(kw)}")
        if mtu is not None:
            attr_actions.append((pk, {"mtu": mtu})); plan.append(f"port {pk}: MTU -> {mtu}")

    # LAGs
    lag_actions = []
    for gk, gc in (cfg.get("lags") or {}).items():
        ports = parse_ports(",".join(str(p) for p in gc["ports"]))
        mode = AGGR_MODE[gc.get("mode", "lacp")]
        lag_actions.append((int(gk), ports, mode))
        plan.append(f"LAG {gk}: ports {fmt_ports(ports)} ({gc.get('mode','lacp')})")

    # ---- report / execute ----
    if not plan:
        print("Already in sync — nothing to do."); return
    print("Plan:")
    for line in plan:
        print(f"  - {line}")
    if args.dry_run:
        print("\n[dry-run] no changes made."); return

    if not args.no_backup:
        blob = sw.get_config_blob()
        bpath = f"qsw-backup-{sw.host}-{time.strftime('%Y%m%d-%H%M%S')}.bin"
        Path(bpath).write_bytes(blob)
        print(f"\nBacked up current config to {bpath} ({len(blob)} bytes)")

    for group, ports, mode in lag_actions:  # LAGs first (they reset member VLANs)
        sw.set_lag(group, ports, mode=mode)
    for v in sorted(to_create, key=int):
        sw.vlan_write(v, tagged=[], untagged=[], action="add")
    for vid in changed_vids:
        tagged = [p for p, t in table[vid].items() if t]
        untag = [p for p, t in table[vid].items() if not t]
        sw.vlan_write(vid, tagged=tagged, untagged=untag, action="edit")
    for pk, kw in attr_actions:
        if "mtu" in kw:
            sw.set_port_mtu([pk], kw["mtu"])
        else:
            sw.set_port([pk], **kw)
    if label_updates:
        names.update(label_updates); save_names(names)
    print(f"\nApplied {len(plan)} change(s).")
    if args.save:
        sw.save(); print("Persisted to startup config.")


def cmd_save(sw, args):
    sw.save()
    print("Running config saved to startup config.")


def cmd_raw(sw, args):
    data = json.loads(args.data) if args.data else None
    res = sw.request(args.method.upper(), args.path, data=data)
    print(json.dumps(res, indent=2))


def build_parser():
    p = argparse.ArgumentParser(description="Programmatic control of a QNAP QSW managed switch.")
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--scheme", default=DEFAULT_SCHEME, choices=["http", "https"])
    p.add_argument("--json", action="store_true", help="raw JSON output where supported")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("vlans", help="list all VLANs").set_defaults(func=cmd_vlans)

    sp = sub.add_parser("vlan", help="show one VLAN"); sp.add_argument("id"); sp.set_defaults(func=cmd_vlan)

    for name, fn, help_ in [("add", cmd_add, "create a VLAN"), ("set", cmd_set, "replace a VLAN's membership")]:
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("id")
        sp.add_argument("--tagged", default="", help="tagged/trunk ports, e.g. '1-4,17'")
        sp.add_argument("--untagged", default="", help="untagged/access ports, e.g. '5,6'")
        sp.add_argument("--save", action="store_true", help="persist to startup config")
        sp.set_defaults(func=fn)

    sp = sub.add_parser("del", help="delete VLAN(s)"); sp.add_argument("ids", nargs="+")
    sp.add_argument("--save", action="store_true"); sp.set_defaults(func=cmd_del)

    sp = sub.add_parser("trunk", help="make a port a tagged member of every VLAN (802.1Q trunk)")
    sp.add_argument("port", help="port to trunk, e.g. '17' or '20' (LAG 3)")
    sp.add_argument("--native", help="VLAN id carried UNtagged on this port (native/PVID)")
    sp.add_argument("--exclude", default="", help="comma-separated VLAN ids to leave untouched")
    sp.add_argument("--dry-run", action="store_true", help="show changes without applying")
    sp.add_argument("--save", action="store_true", help="persist to startup config")
    sp.set_defaults(func=cmd_trunk)

    sp = sub.add_parser("access", help="make a port an untagged access member of ONE VLAN (removed from all others)")
    sp.add_argument("port", help="port to set, e.g. '5'")
    sp.add_argument("vlan", help="the single VLAN id the port carries untagged")
    sp.add_argument("--dry-run", action="store_true", help="show changes without applying")
    sp.add_argument("--save", action="store_true", help="persist to startup config")
    sp.set_defaults(func=cmd_access)

    sp = sub.add_parser("mtu", help="show or set per-port MTU (max frame size)")
    sp.add_argument("ports", help="port(s), e.g. '17' or '1-16'")
    sp.add_argument("value", nargs="?", help=f"MTU to set ({MTU_MIN}-{MTU_MAX}); omit to show current")
    sp.add_argument("--dry-run", action="store_true", help="show changes without applying")
    sp.add_argument("--save", action="store_true", help="persist to startup config")
    sp.set_defaults(func=cmd_mtu)

    sp = sub.add_parser("name", help="set/show LOCAL VLAN name labels (switch stores no VLAN names)")
    sp.add_argument("vlan", nargs="?", help="numeric VLAN id")
    sp.add_argument("label", nargs="?", help="label to assign; omit to show")
    sp.add_argument("--list", action="store_true", help="list all labels")
    sp.add_argument("--clear", action="store_true", help="remove this VLAN's label")
    sp.set_defaults(func=cmd_name)

    sp = sub.add_parser("port", help="show or set port state (enable/disable, speed, flow-control)")
    sp.add_argument("ports", help="port(s), e.g. '3' or '1-16'")
    g = sp.add_mutually_exclusive_group()
    g.add_argument("--enable", action="store_true", help="bring port up (no shutdown)")
    g.add_argument("--disable", action="store_true", help="shut port down")
    sp.add_argument("--flow-control", choices=["on", "off"], help="802.3x flow control")
    sp.add_argument("--speed", choices=list(SPEED_MAP), help="force speed or 'auto'")
    sp.add_argument("--dry-run", action="store_true", help="show changes without applying")
    sp.add_argument("--save", action="store_true", help="persist to startup config")
    sp.set_defaults(func=cmd_port)

    sub.add_parser("neighbors", help="LLDP neighbors (what's plugged into each port)").set_defaults(func=cmd_neighbors)
    sub.add_parser("health", help="temperature and fan status").set_defaults(func=cmd_health)

    sp = sub.add_parser("macs", help="learned MAC address table (MAC / VLAN / port)")
    sp.add_argument("--port", help="filter by port(s), e.g. '3' or '1-8'")
    sp.add_argument("--vlan", help="filter by VLAN id or name")
    sp.add_argument("--mac", help="filter by MAC substring")
    sp.set_defaults(func=cmd_macs)

    sp = sub.add_parser("find", help="find which port/VLAN a MAC (or fragment) is on")
    sp.add_argument("mac", help="full or partial MAC, e.g. 'a0:ad:9f' or a full address")
    sp.set_defaults(func=cmd_find)

    lag_p = sub.add_parser("lag", help="link aggregation groups (bond ports)")
    lag_sub = lag_p.add_subparsers(dest="lagcmd")
    lag_p.set_defaults(func=cmd_lag_list)
    lag_sub.add_parser("list", help="show all LAG groups").set_defaults(func=cmd_lag_list)
    lp = lag_sub.add_parser("set", help="create/replace a LAG group")
    lp.add_argument("group", type=int, help="group number 1-8")
    lp.add_argument("ports", help="member ports (>=2), e.g. '7,8'")
    lp.add_argument("--mode", choices=list(AGGR_MODE), default="lacp", help="LACP (active) or static")
    lp.add_argument("--dry-run", action="store_true")
    lp.add_argument("--save", action="store_true")
    lp.set_defaults(func=cmd_lag_set)
    lp = lag_sub.add_parser("del", help="delete a LAG group")
    lp.add_argument("group", type=int)
    lp.add_argument("--save", action="store_true")
    lp.set_defaults(func=cmd_lag_del)

    sp = sub.add_parser("apply", help="reconcile the switch to a declarative switch.yaml")
    sp.add_argument("file", help="path to switch.yaml")
    sp.add_argument("--dry-run", action="store_true", help="show the plan without applying")
    sp.add_argument("--no-backup", action="store_true", help="skip the pre-apply config backup")
    sp.add_argument("--save", action="store_true", help="persist to startup config after applying")
    sp.set_defaults(func=cmd_apply)

    sp = sub.add_parser("backup", help="download full config backup to a file")
    sp.add_argument("file", nargs="?", help="output path (default: timestamped)")
    sp.set_defaults(func=cmd_backup)

    sp = sub.add_parser("restore", help="restore a config backup (DESTRUCTIVE, reboots)")
    sp.add_argument("file", help="backup file to upload")
    sp.add_argument("--yes", action="store_true", help="confirm the destructive restore")
    sp.set_defaults(func=cmd_restore)

    sub.add_parser("ports", help="port status table").set_defaults(func=cmd_ports)
    sub.add_parser("save", help="persist running->startup config").set_defaults(func=cmd_save)

    sp = sub.add_parser("raw", help="call any /api/v1 endpoint directly")
    sp.add_argument("method"); sp.add_argument("path")
    sp.add_argument("--data", help="JSON request body")
    sp.set_defaults(func=cmd_raw)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    sw = QSW(host=args.host, scheme=args.scheme)
    try:
        args.func(sw, args)
    except (QSWError, requests.RequestException) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

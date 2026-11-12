"""#439: safe single-poller Telegram cutover to a dedicated static Linux UID.

Phases:
  inspect  : read-only, no credentials or state contents printed
  prepare  : root-owned immutable snapshot of LIVE .py files + static account
  cutover  : stop ONE poller, copy complete private state, install one drop-in,
             restart the SAME service, rollback automatically on validation failure
  rollback : stop static bot, remove only this drop-in, restart old DynamicUser.

Requires an approved branch→PR→main merge before running mutating phases.
Never use this against a repository checkout as an active deployment.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import pwd
import grp
import re
import shutil
import stat
import subprocess
import sys
import time

SERVICE = "browser-vps-telegram-bot.service"
USER = "bvp_telegram_bot"
STATE_OLD = Path("/var/lib/private/browser-vps-telegram-bot")
STATE_NEW = Path("/var/lib/bvp-telegram-bot-v2")
BOT_ROOT = Path("/opt/browser-vps-telegram-bot")
RELEASES = BOT_ROOT / "releases"
CURRENT = BOT_ROOT / "current"
OLD_ENTRY = BOT_ROOT / "bot.py"
DROPIN = Path("/etc/systemd/system/browser-vps-telegram-bot.service.d/zz-issue439-static-user.conf")
BACKUPS = Path("/var/backups/browser-vps-telegram-issue439")
ALLOWED_GROUPS = {
    "browser-vps-passkey-ipc",
    "browser-vps-backup-request",
    "browser-vps-telegram-state",
}
OFFLINE = (
    "bot.py", "coadmin.py", "coadmin_pg_connection.py", "telegram_state_store.py", "webapp_init_data.py",
)
# Filenames come from the current live state, NOT an outdated sqlite-only
# migration manifest. Preserve all existing private files; unknowns STOP.
STATE_FILES = {
    "offset": 128,
    "coadmins.sqlite3": 32 * 1024 * 1024,
    "user_activity.json": 1024 * 1024,
    "security_events.json": 2 * 1024 * 1024,
    "passkey-notified.json": 1024 * 1024,
    "coadmin-e2e.log": 2 * 1024 * 1024,
}
DROPIN_TEXT = """# Issue #439: root-owned, separately reviewed single-bot cutover.
# Keep all preexisting base unit, credentials, sandbox and group drop-ins.
[Service]
DynamicUser=no
User=bvp_telegram_bot
Group=bvp_telegram_bot
StateDirectory=
StateDirectory=bvp-telegram-bot-v2
StateDirectoryMode=0700
ExecStart=
ExecStart=/usr/bin/python3 -B /opt/browser-vps-telegram-bot/current/bot.py
"""


class CutoverDenied(Exception):
    pass


def run(*argv: str) -> str:
    result = subprocess.run(argv, text=True, capture_output=True, timeout=20)
    if result.returncode:
        raise CutoverDenied("COMMAND_FAILED: " + argv[0] + " " + argv[1])
    return result.stdout.strip()


def props() -> dict[str, str]:
    names = ("ActiveState", "MainPID", "User", "Group", "DynamicUser",
             "StateDirectory", "StateDirectoryMode", "SupplementaryGroups",
             "ExecStart", "NRestarts", "ProtectSystem", "ProtectHome",
             "PrivateTmp", "NoNewPrivileges", "UMask")
    raw = run("systemctl", "show", SERVICE,
              *(f"-p{x}" for x in names), "--no-pager")
    return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)


def _secure_dir(root: Path, mode: int, *, uid: int = 0, gid: int = 0):
    root.mkdir(mode=mode, parents=True, exist_ok=True)
    st = root.lstat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != uid or st.st_gid != gid
            or (st.st_mode & 0o777) != mode):
        raise CutoverDenied("DIRECTORY_OWNERSHIP_OR_MODE")


def _read_file(path: Path, *, limit: int, private: bool) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(stream.fileno())
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_size > limit or st.st_size <= 0
                or (private and (st.st_mode & 0o077))
                or (not private and (st.st_mode & 0o022))):
            raise CutoverDenied("INVALID_FILE_METADATA")
        data = stream.read(limit + 1)
    if len(data) > limit or not data:
        raise CutoverDenied("INVALID_FILE_LENGTH")
    return data


def _write_new(path: Path, data: bytes, uid: int, gid: int, mode: int):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    if hashlib.sha256(_read_file(path, limit=max(1, len(data)), private=mode == 0o600)).digest() != hashlib.sha256(data).digest():
        raise CutoverDenied("COPY_INTEGRITY_FAILED")


def _pollers() -> list[int]:
    found = []
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal():
            continue
        try:
            args = (process / "cmdline").read_bytes().split(b"\0")
        except (OSError, PermissionError):
            continue
        if any(x in (
            b"/opt/browser-vps-telegram-bot/bot.py",
            b"/opt/browser-vps-telegram-bot/current/bot.py"
        ) for x in args):
            found.append(int(process.name))
    return found


def _source_state() -> dict[str, bytes]:
    # systemd DynamicUser may ID-map the directory to nobody outside its
    # own mount namespace. Root can read it after the sole poller stops.
    root = STATE_OLD
    st = root.lstat()
    if not stat.S_ISDIR(st.st_mode) or root.is_symlink():
        raise CutoverDenied("UNEXPECTED_LEGACY_STATE")
    names = {x.name for x in root.iterdir()}
    if not names or not names.issubset(STATE_FILES) or "offset" not in names:
        raise CutoverDenied("UNKNOWN_STATE_FILE_NEEDS_MANUAL_REVIEW")
    data = {name: _read_file(root / name, limit=STATE_FILES[name], private=True)
            for name in sorted(names)}
    cursor = data["offset"].decode("ascii").strip()
    if not cursor.isdecimal() or len(cursor) > 32:
        raise CutoverDenied("BAD_OFFSET")
    return data


def inspect():
    p = props()
    if (p.get("ActiveState") != "active" or p.get("DynamicUser") != "yes"
            or p.get("StateDirectory") != "browser-vps-telegram-bot"
            or p.get("User") != "browser-vps-telegram-bot"
            or set(p.get("SupplementaryGroups", "").split()) != ALLOWED_GROUPS
            or len(_pollers()) != 1
            or str(_pollers()[0]) != p.get("MainPID")
            or p.get("ProtectSystem") != "strict"
            or p.get("ProtectHome") != "yes"
            or p.get("PrivateTmp") != "yes"
            or p.get("NoNewPrivileges") != "yes"
            or p.get("UMask") != "0077"
            or "/opt/browser-vps-telegram-bot/bot.py" not in p.get("ExecStart", "")
            or DROPIN.exists()):
        raise CutoverDenied("EXISTING_SERVICE_DRIFT")
    if not STATE_OLD.is_dir() or STATE_NEW.exists():
        raise CutoverDenied("UNEXPECTED_STATE_LOCATION")
    if run("systemctl", "is-active", "browser-vps-telegram-state-bridge.service") != "active":
        raise CutoverDenied("POSTGRESQL_STATE_BRIDGE_NOT_ACTIVE")
    # These are network-bound services and must remain untouched.
    if not (Path("/run/browser-vps-telegram-state/state.sock").is_socket()
            and Path("/run/browser-vps-passkey-links/links.sock").is_socket()):
        raise CutoverDenied("MISSING_REQUIRED_IPC")
    print("PREFLIGHT_OK one_poller=1 dynamic_user=1 pg_state_bridge=active")
    print("STATE_FILENAME_SET", ",".join(sorted(x.name for x in STATE_OLD.iterdir())))
    print("NO_PRIVATE_VALUES_DISPLAYED")


def prepare():
    if os.geteuid() != 0:
        raise CutoverDenied("ROOT_REQUIRED")
    inspect()
    if CURRENT.exists() or CURRENT.is_symlink() or BACKUPS.exists():
        raise CutoverDenied("TARGET_ALREADY_PREPARED")
    try:
        pwd.getpwnam(USER)
    except KeyError:
        run("useradd", "--system", "--user-group", "--no-create-home",
            "--home-dir", str(STATE_NEW), "--shell", "/usr/sbin/nologin", USER)
    account = pwd.getpwnam(USER)
    group = grp.getgrnam(USER)
    if (account.pw_uid <= 0 or account.pw_gid != group.gr_gid
            or account.pw_shell != "/usr/sbin/nologin"
            or account.pw_dir != str(STATE_NEW)):
        raise CutoverDenied("STATIC_USER_CONFIG_UNEXPECTED")
    # No change to /etc/group; existing systemd SupplementaryGroups are
    # the only route to the three restricted IPC sockets.
    _secure_dir(RELEASES, 0o755)
    sources = sorted(BOT_ROOT.glob("*.py"))
    if not {p.name for p in sources}.issuperset(OFFLINE):
        raise CutoverDenied("INCOMPLETE_BOT_SOURCE")
    if any(path.lstat().st_uid != 0 for path in sources):
        raise CutoverDenied("NONROOT_PRODUCTION_SOURCE")
    blobs = {p.name: _read_file(p, limit=2 * 1024 * 1024, private=False)
             for p in sources}
    manifest = b"".join((name + " " + hashlib.sha256(raw).hexdigest() + "\n").encode()
                        for name, raw in sorted(blobs.items()))
    release_sha = hashlib.sha256(manifest).hexdigest()
    dest = RELEASES / release_sha
    if dest.exists() or dest.is_symlink():
        raise CutoverDenied("RELEASE_ALREADY_EXISTS")
    dest.mkdir(mode=0o755)
    for name, raw in blobs.items():
        _write_new(dest / name, raw, 0, 0, 0o644)
    _write_new(dest / "SOURCE_SHA256", manifest, 0, 0, 0o644)
    (BOT_ROOT / (".current-" + release_sha)).symlink_to("releases/" + release_sha)
    os.replace(BOT_ROOT / (".current-" + release_sha), CURRENT)
    _secure_dir(BACKUPS, 0o700)
    _write_new(BACKUPS / "original-base-unit",
               _read_file(Path("/etc/systemd/system") / SERVICE,
                          limit=1024 * 1024, private=False), 0, 0, 0o600)
    _write_new(BACKUPS / "source-manifest", manifest, 0, 0, 0o600)
    # A prior unit/drop-in change between prepare and cutover must abort,
    # including any changes to LoadCredential, IPC groups or environment.
    _write_new(BACKUPS / "merged-unit-before",
               run("systemctl", "cat", SERVICE).encode(), 0, 0, 0o600)
    print("PREPARED_STATIC_ACCOUNT release_sha256=" + release_sha)
    print("NO_SERVICE_RESTART_OR_PRIVATE_STATE_ACCESS")


def _prepared():
    account = pwd.getpwnam(USER)
    if (account.pw_uid <= 0 or account.pw_shell != "/usr/sbin/nologin"
            or CURRENT.is_symlink() is False):
        raise CutoverDenied("STATIC_ACCOUNT_OR_RELEASE_MISSING")
    release = CURRENT.resolve(strict=True)
    if release.parent != RELEASES or not re.fullmatch("[0-9a-f]{64}", release.name):
        raise CutoverDenied("UNEXPECTED_RELEASE_PATH")
    if (release.lstat().st_uid != 0
            or release.stat().st_mode & 0o777 != 0o755):
        raise CutoverDenied("RELEASE_OWNERSHIP")
    manifest = _read_file(release / "SOURCE_SHA256", limit=32768, private=False)
    if hashlib.sha256(manifest).hexdigest() != release.name:
        raise CutoverDenied("RELEASE_MANIFEST_MISMATCH")
    manifest_entries = {}
    for line in manifest.decode("ascii").strip().splitlines():
        name, sha = line.split(" ")
        if ("/" in name or not name.endswith(".py") or
                not re.fullmatch("[0-9a-f]{64}", sha)):
            raise CutoverDenied("RELEASE_FILENAME")
        actual = _read_file(release / name, limit=2 * 1024 * 1024, private=False)
        if (hashlib.sha256(actual).hexdigest() != sha
                or (release / name).stat().st_uid != 0):
            raise CutoverDenied("RELEASE_CHANGED")
        manifest_entries[name] = sha
    if set(manifest_entries) | {"SOURCE_SHA256"} != {
            item.name for item in release.iterdir()}:
        raise CutoverDenied("RELEASE_UNEXPECTED_FILES")
    # The original executable might have changed after initial prepare;
    # this cutover may only deploy the exact LIVE code reviewed in prepare.
    live = {f.name for f in BOT_ROOT.glob("*.py")}
    if set(manifest_entries) != live:
        raise CutoverDenied("LIVE_CODE_FILE_LIST_CHANGED")
    for name, original_sha in manifest_entries.items():
        if (BOT_ROOT / name).lstat().st_uid != 0:
            raise CutoverDenied("LIVE_CODE_OWNER_CHANGED")
        if hashlib.sha256(_read_file(
                BOT_ROOT / name, limit=2 * 1024 * 1024,
                private=False)).hexdigest() != original_sha:
            raise CutoverDenied("LIVE_CODE_CHANGED_SINCE_PREPARE")
    if not BACKUPS.is_dir() or (BACKUPS.stat().st_mode & 0o777) != 0o700:
        raise CutoverDenied("BACKUP_AREA_MISSING")
    # Do not silently inherit a modified credentials/drop-in configuration.
    observed = run("systemctl", "cat", SERVICE).encode()
    expected = _read_file(BACKUPS / "merged-unit-before",
                          limit=1024 * 1024, private=True)
    if observed != expected:
        raise CutoverDenied("LIVE_SYSTEMD_UNIT_CHANGED_SINCE_PREPARE")
    return account


def _stop_only_existing():
    run("systemctl", "stop", SERVICE)
    if props().get("MainPID") not in ("0", None) or _pollers():
        raise CutoverDenied("BOT_STILL_RUNNING_AFTER_STOP")


def _restore_dynamic():
    if DROPIN.exists():
        if DROPIN.read_text() != DROPIN_TEXT:
            raise CutoverDenied("UNKNOWN_SYSTEMD_DROPIN")
        DROPIN.unlink()
    run("systemctl", "daemon-reload")
    run("systemctl", "start", SERVICE)
    # The authoritative offset is in PostgreSQL and must NOT be rolled
    # back from any old local JSON or SQLite backup.
    p = props()
    if (p.get("ActiveState") != "active" or p.get("DynamicUser") != "yes"
            or len(_pollers()) != 1):
        raise CutoverDenied("OLD_BOT_RESTART_NOT_CONFIRMED")


def _process_access(pid: int, uid: int, primary_gid: int,
                    allowed_groups: set[int],
                    proc_root: Path = Path("/proc")) -> bool:
    """Read OS-effective UID and groups, not merely systemd configuration."""
    try:
        if type(pid) is not int or pid <= 1 or type(uid) is not int:
            return False
        text = (proc_root / str(pid) / "status").read_text()
        data = dict(line.split(":", 1) for line in text.splitlines() if ":" in line)
        actual_uid = [int(x) for x in data["Uid"].split()]
        actual_gid = [int(x) for x in data["Gid"].split()]
        actual_groups = {int(x) for x in data["Groups"].split()}
        return (len(actual_uid) == 4 and len(actual_gid) == 4
                and all(x == uid for x in actual_uid)
                and all(x == primary_gid for x in actual_gid)
                and actual_groups == allowed_groups)
    except (OSError, KeyError, ValueError):
        return False


def cutover():
    if os.geteuid() != 0:
        raise CutoverDenied("ROOT_REQUIRED")
    inspect()
    account = _prepared()
    if DROPIN.exists() or STATE_NEW.exists():
        raise CutoverDenied("ALREADY_CUTOVER_OR_STATE_EXISTS")
    _stop_only_existing()
    stopped = True
    try:
        state = _source_state()
        _secure_dir(BACKUPS, 0o700)
        snapshot = BACKUPS / "state-snapshot"
        _secure_dir(snapshot, 0o700)
        for name, raw in state.items():
            _write_new(snapshot / name, raw, 0, 0, 0o600)
        # Original file snapshots remain 0600 root-only. The live v2 state
        # is copied with user-owned 0600 files, no symlinks / no old data
        # removal. Actual Telegram "offset" is authoritative in PG bridge.
        STATE_NEW.mkdir(mode=0o700)
        os.chown(STATE_NEW, account.pw_uid, account.pw_gid)
        os.chmod(STATE_NEW, 0o700)
        for name, raw in state.items():
            _write_new(STATE_NEW / name, raw, account.pw_uid, account.pw_gid, 0o600)
        if {k: hashlib.sha256(v).digest() for k, v in _source_state().items()} != {
                k: hashlib.sha256(v).digest() for k, v in state.items()}:
            raise CutoverDenied("SOURCE_STATE_CHANGED_WHILE_STOPPED")
        _write_new(DROPIN, DROPIN_TEXT.encode(), 0, 0, 0o644)
        run("systemctl", "daemon-reload")
        run("systemd-analyze", "verify", SERVICE)
        run("systemctl", "start", SERVICE)
        time.sleep(2)
        p = props()
        if (p.get("ActiveState") != "active" or p.get("DynamicUser") != "no"
                or p.get("User") != USER or p.get("StateDirectory") != STATE_NEW.name
                or p.get("StateDirectoryMode") != "0700"
                or set(p.get("SupplementaryGroups", "").split()) != ALLOWED_GROUPS
                or len(_pollers()) != 1
                or str(_pollers()[0]) != p.get("MainPID")
                or not _process_access(
                    int(p["MainPID"]), account.pw_uid, account.pw_gid,
                    {account.pw_gid} |
                    {grp.getgrnam(name).gr_gid for name in ALLOWED_GROUPS}
                )
                or run("systemctl", "is-active",
                       "browser-vps-telegram-state-bridge.service") != "active"):
            raise CutoverDenied("STATIC_BOT_POSTFLIGHT_FAILED")
        print("CUTOVER_PASS static_uid=" + str(account.pw_uid))
        print("ONE_POLLING_SERVICE_ONLY; PG_OFFSET_NOT_CHANGED_OR_RESTORED")
    except BaseException:
        if stopped:
            try:
                run("systemctl", "stop", SERVICE)
                _restore_dynamic()
                print("AUTOMATIC_ROLLBACK_OLD_DYNAMICUSER_RESTORED")
            except Exception:
                print("ROLLBACK_UNCONFIRMED_OPERATOR_ACTION_REQUIRED", file=sys.stderr)
        raise


def rollback():
    if os.geteuid() != 0:
        raise CutoverDenied("ROOT_REQUIRED")
    if not DROPIN.exists() or DROPIN.read_text() != DROPIN_TEXT:
        raise CutoverDenied("NO_MATCHING_CUTOVER_DROPIN")
    _stop_only_existing()
    _restore_dynamic()
    print("ROLLBACK_OLD_DYNAMICUSER_RESTORED")
    print("NO_POSTGRESQL_ORIGINAL_CURSOR_RESTORE_PERFORMED")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("inspect", "prepare", "cutover", "rollback"))
    args = parser.parse_args()
    try:
        globals()[args.action]()
    except (OSError, ValueError, KeyError, CutoverDenied) as exc:
        print("DENIED", type(exc).__name__, str(exc) if isinstance(exc, CutoverDenied) else "",
              file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()

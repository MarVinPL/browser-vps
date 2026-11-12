"""Owner-approved one-time Telegram co-admin invitations."""
import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import string
import sqlite3
import time

TTL = 600
MAX_TTL = 72 * 3600

def parse_duration(raw):
    parts = raw.split()
    if len(parts) == 1 and parts[0] == "/invite_admin":
        return TTL, "10 minut"
    if len(parts) != 2 or parts[0] != "/invite_admin":
        return None
    value = parts[1].lower()
    if len(value) < 2 or value[-1] not in ("m", "h", "d") or not value[:-1].isdecimal():
        return None
    n = int(value[:-1])
    seconds = n * {"m":60, "h":3600, "d":86400}[value[-1]]
    if not 60 <= seconds <= MAX_TTL:
        return None
    unit = {"m":"min", "h":"godz.", "d":"dni"}[value[-1]]
    return seconds, f"{n} {unit}"


def db_path():
    root = os.environ.get("STATE_DIRECTORY", "").split(":")[0]
    if not root or not pathlib.Path(root).is_absolute():
        raise RuntimeError("MISSING_STATE_DIRECTORY")
    return pathlib.Path(root) / "coadmins.sqlite3"

def connect():
    # The live source of truth is PostgreSQL; fail closed on connection issues.
    # SQLite is retained OFFLINE for rollback and is never read for RBAC.
    if __package__:
        from . import coadmin_pg_connection
    else:
        import coadmin_pg_connection
    return coadmin_pg_connection.connect()

def failed_code_alert(request,token,owner,uid,sender,reason):
    if uid==owner or type(uid) is not int or uid<=0:
        return
    now=int(time.time())
    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        con.execute("DELETE FROM denied_alerts WHERE last_at<?",(now-3600,))
        last=con.execute("SELECT last_at FROM denied_alerts WHERE uid=?",(uid,)).fetchone()
        total=con.execute("SELECT COUNT(*) FROM denied_alerts").fetchone()[0]
        if (last and now-last[0]<600) or (not last and total>=15):
            return
        con.execute("INSERT INTO denied_alerts(uid,last_at) VALUES(?,?) ON CONFLICT(uid) DO UPDATE SET last_at=excluded.last_at",(uid,now))
    username=sender.get("username") if isinstance(sender,dict) else None
    name="@"+username if isinstance(username,str) and 1<=len(username)<=64 and username.replace("_","").isalnum() else "brak nazwy"
    try:
        send(request,token,owner,"⚠️ Nieudana próba /join_admin\nTelegram ID: "+str(uid)+"\nNazwa: "+name+"\nPowód: "+reason+"\nKod nie jest zapisywany ani przesyłany. Limit alertów: raz na 10 min na użytkownika, do 15 różnych użytkowników na godzinę.")
    except RuntimeError:
        print("COADMIN_FAILED_CODE_ALERT_DELIVERY_FAILED",flush=True)

def trace(event,invite_id=None,uid=None,detail=None):
    # Do not log invitation codes, bearer tokens, callback nonces or message bodies.
    safe_events={"created","regenerated","cancelled","approve","reject","join_accepted","join_rejected","failed_code_attempt","owner_alert_attempt","owner_alert_sent","owner_alert_failed"}
    if event not in safe_events:
        return
    fields=["COADMIN_E2E",f"event={event}",f"at={int(time.time())}"]
    if invite_id is not None:
        fields.append(f"invite_id={int(invite_id)}")
    if uid is not None:
        fields.append(f"uid={int(uid)}")
    if detail in ("expired","invalid","rate_limited","invalid_format"):
        fields.append(f"reason={detail}")
    print(" ".join(fields),flush=True)
    # Persist minimal, redacted evidence independently of journald rotation.
    try:
        path=db_path().parent / "coadmin-e2e.log"
        fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_CLOEXEC,0o600)
        try:
            os.write(fd,(" ".join(fields)+"\n").encode("ascii"))
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        print("COADMIN_E2E_PERSIST_FAILED",flush=True)

def audit(con,ident,action,actor,subject=None):
    con.execute("INSERT INTO invite_history(invite_id,action,actor_id,subject_id,at) VALUES(?,?,?,?,?)",(ident,action,actor,subject,int(time.time())))
    trace(action,ident,subject if subject is not None else actor)

def decide_invitation(owner, action, nonce, now):
    """Commit one decision before any Telegram success or keyboard change.

    The digest is presentation/audit evidence only, never a new authorization
    token. Historical rows without it cannot reliably identify an old callback.
    """
    outcome = "Zgłoszenie zostało już rozpatrzone albo zaproszenie jest nieważne."
    notice = None
    clear_buttons = False
    digest = hashlib.sha256(nonce.encode()).hexdigest()
    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        receipt = con.execute(
            "SELECT action,subject_id FROM invite_history WHERE decision_nonce_hash=? "
            "AND actor_id=? AND action IN ('approve','reject') ORDER BY id DESC LIMIT 1",
            (digest, owner)).fetchone()
        if receipt:
            result = "zatwierdzone" if receipt[0] == "approve" else "odrzucone"
            outcome = f"Zgłoszenie zostało już {result}. Decyzji nie zmieniono."
            clear_buttons = True
        else:
            row = con.execute(
                "SELECT id,pending_uid,pending_until,nonce,expires FROM invitations WHERE nonce=?",
                (nonce,)).fetchone()
            if (row and row[1] and row[2] is not None
                    and secrets.compare_digest(row[3] or "", nonce) and row[1] != owner):
                if row[2] < now:
                    outcome = "Termin decyzji dla tego zgłoszenia upłynął."
                    clear_buttons = True
                else:
                    uid = row[1]
                    if action == "approve":
                        con.execute("INSERT OR IGNORE INTO members(uid,joined_at) VALUES(?,?)", (uid,now))
                        outcome = "✅ Potwierdzono współadministratora. ID: " + str(uid)
                    else:
                        outcome = "❌ Zaproszenie odrzucone. ID: " + str(uid)
                    con.execute(
                        "INSERT INTO invite_history(invite_id,action,actor_id,subject_id,at,decision_nonce_hash) "
                        "VALUES(?,?,?,?,?,?)", (row[0],action,owner,uid,now,digest))
                    con.execute("DELETE FROM invitations WHERE id=?", (row[0],))
                    notice = (uid, action, row[0])
                    clear_buttons = True
    # __exit__ has committed. A failed commit must not announce a decision.
    if notice:
        trace(notice[1], notice[2], notice[0])
    return outcome, notice, clear_buttons


def generate_invite_code():
    alphabet=string.ascii_letters+string.digits
    return "".join(secrets.choice(alphabet) for _ in range(32))

def miniapp_invite_start_param(invite_id, token, invite_hash):
    """Create a public locator bound to the current invite generation, never the bearer code."""
    if type(invite_id) is not int or not 1 <= invite_id < 2**63:
        return None
    if (not isinstance(token, str) or not token
            or not isinstance(invite_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", invite_hash)):
        return None
    message = (b"bvp-miniapp-invite:v1:" + str(invite_id).encode("ascii")
               + b":" + invite_hash.encode("ascii"))
    tag = hmac.new(token.encode("utf-8"), message, hashlib.sha256).hexdigest()[:32]
    return "i1_" + str(invite_id) + "_" + tag


def parse_miniapp_invite_start_param(start_param):
    """Parse a public invite locator; its MAC is checked against the current DB hash."""
    if not isinstance(start_param, str):
        return None
    match = re.fullmatch(r"i1_([1-9][0-9]{0,18})_([0-9a-f]{32})", start_param)
    if not match:
        return None
    invite_id = int(match.group(1))
    if invite_id >= 2**63:
        return None
    return invite_id, match.group(2)


def verify_miniapp_invite_start_param(start_param, token, invite_hash):
    """Verify locator integrity for a specific invite generation."""
    parsed = parse_miniapp_invite_start_param(start_param)
    if not parsed:
        return None
    invite_id, _ = parsed
    expected = miniapp_invite_start_param(invite_id, token, invite_hash)
    return invite_id if expected and hmac.compare_digest(expected, start_param) else None


def miniapp_invite_locator_matches(invite_id, token, invite_hash, invite_tag):
    expected = miniapp_invite_start_param(invite_id, token, invite_hash)
    supplied = ("i1_" + str(invite_id) + "_" + invite_tag
                if isinstance(invite_tag, str) else "")
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def miniapp_invite_url(request, token, invite_id, code):
    """Return a test-only startapp link; production links stay disabled in this PR."""
    if os.environ.get("BVP_TELEGRAM_TEST_MODE") != "1":
        return None
    expected_url = "https://148-113-182-137.sslip.io/vps-telegram-test/mini"
    configured_url = os.environ.get("BVP_TELEGRAM_TEST_MINI_APP_URL", "").rstrip("/")
    if configured_url != expected_url:
        return None
    if not isinstance(code, str) or not code:
        return None
    invite_hash = hashlib.sha256(code.encode()).hexdigest()
    start_param = miniapp_invite_start_param(invite_id, token, invite_hash)
    if not start_param:
        return None
    try:
        me = request(token, "getMe", {})
    except RuntimeError:
        return None
    username = me.get("username") if isinstance(me, dict) else None
    if (not isinstance(me, dict) or me.get("has_main_web_app") is not True
            or not isinstance(username, str)
            or not 5 <= len(username) <= 32
            or not all(c in string.ascii_letters + string.digits + "_" for c in username)):
        return None
    return "https://t.me/" + username + "?startapp=" + start_param


def invitation_message(code,expires,seconds,ident=None,regenerated=False,miniapp_url=None):
    title=(f"🔄 Nowy kod dla zaproszenia #{ident}" if regenerated else "🔐 Kod jednorazowy")
    note="\nPoprzedni kod został unieważniony. Termin ważności bez zmian." if regenerated else ""
    app_note=("\n\n📱 Otwórz zaproszenie w Telegram Mini App:\n"+miniapp_url
              if miniapp_url else "")
    return (title+": "+code+time_details(expires,seconds)+note+app_note+
        "\n\n📋 Instrukcja dla zapraszanej osoby:"+
        "\n1. Otwórz Telegram i znajdź bota Browser VPS."+
        "\n2. Jeśli link Mini App jest dostępny, otwórz go; w przeciwnym razie wyślij: /join_admin "+code+
        "\n3. Poczekaj na decyzję właściciela. Bot powiadomi Cię o zatwierdzeniu albo odrzuceniu."+
        "\n\n⚠️ Sam kod nie daje dostępu. Prześlij go tylko zaufanej osobie.")

def rotate_invite(token,owner,request,ident,now):
    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        row=con.execute("SELECT expires,pending_uid,issued_seconds FROM invitations WHERE id=?",(ident,)).fetchone()
        if not row or row[0]<now or row[1] is not None:
            send(request,token,owner,"Nie można odnowić: zaproszenie nieaktywne lub już zgłoszone.")
            return
        new=generate_invite_code()
        con.execute("UPDATE invitations SET hash=? WHERE id=?",(hashlib.sha256(new.encode()).hexdigest(),ident))
        audit(con,ident,"regenerated",owner)
    send(request,token,owner,invitation_message(new,row[0],row[2],ident,True,miniapp_invite_url(request,token,ident,new)))

def expiry_time(expires):
    import datetime, zoneinfo
    return datetime.datetime.fromtimestamp(expires,zoneinfo.ZoneInfo("Europe/Warsaw")).strftime("%d.%m.%Y %H:%M (Warszawa)")

def duration_label(seconds):
    hours, minutes = divmod(max(0, int(seconds)) // 60, 60)
    return f"{hours} godz. {minutes} min" if hours else f"{minutes} min"

def time_details(expires,seconds):
    if seconds is None:
        issued="nieznany (starsze zaproszenie)"
    elif seconds%86400==0:
        issued=f"{seconds//86400} dni"
    elif seconds%3600==0:
        issued=f"{seconds//3600} godz."
    else:
        issued=f"{seconds//60} min"
    return f"\nWydane na: {issued}\nWygasa: {expiry_time(expires)}"

def remaining(expires,now):
    v=max(0,expires-now)
    return f"{v//3600}h {(v%3600)//60}min"

def show_pending(token,owner,request,now):
    with connect() as con:
        rows=con.execute("SELECT id,expires,pending_uid,pending_name,pending_until,nonce,issued_seconds FROM invitations WHERE expires>=? OR pending_until>=? ORDER BY id DESC LIMIT 30",(now,now)).fetchall()
    if not rows:
        send(request,token,owner,"📭 Brak aktywnych zaproszeń.")
        return
    send(request,token,owner,f"📋 Aktywne zaproszenia: {len(rows)}")
    for ident,expires,uid,name,until,nonce,seconds in rows:
        if uid is None:
            send(request,token,owner,f"🔐 Zaproszenie #{ident}: kod jeszcze niewykorzystany. Pozostało: {remaining(expires,now)}{time_details(expires,seconds)}",[ [{"text":"🔄 Nowy kod","callback_data":f"admin:rotate:{ident}"}] ])
        elif until is not None and until>=now and nonce:
            send(request,token,owner,f"⏳ Zaproszenie #{ident}: oczekuje na zatwierdzenie\nID: {uid}\nNazwa: {name or 'brak'}\nPozostało: {remaining(until,now)}\nTermin decyzji: {expiry_time(until)}\nPierwotna ważność kodu: {time_details(expires,seconds)}",[
                [{"text":"✅ Zatwierdź","callback_data":"admin:approve:"+nonce},{"text":"❌ Odrzuć","callback_data":"admin:reject:"+nonce}]])
        else:
            send(request,token,owner,f"⌛ Zaproszenie #{ident}: zgłoszenie wygasło.{time_details(expires,seconds)}")

def is_admin(uid, owner):
    if type(uid) is not int or uid <= 0 or uid == owner:
        return False
    with connect() as con:
        return con.execute("SELECT 1 FROM members WHERE uid=?", (uid,)).fetchone() is not None

def send(request, token, uid, msg, keyboard=None):
    payload = {"chat_id":uid, "text":msg}
    if keyboard:
        payload["reply_markup"] = {"inline_keyboard":keyboard}
    request(token,"sendMessage",payload)

ADMINS_PAGE_SIZE = 5  # Maximum 5 on-demand Bot API calls per list/refresh.


def admin_profile_cache_path():
    # The already private systemd StateDirectory (0600 file), not a new DB.
    return db_path().parent / "admin_profiles_v1.json"


def admin_profile_is_valid(uid, profile):
    return (isinstance(profile, dict) and type(profile.get("id")) is int
            and profile["id"] == uid and profile.get("type") == "private")


def admin_profile_text(uid, profile):
    """Render labels, never use user-supplied names for authorization."""
    if not admin_profile_is_valid(uid, profile):
        profile = {}

    def clean(value):
        if not isinstance(value, str):
            return ""
        return "".join(char for char in value if char.isprintable()).strip()[:64]

    name = " ".join(part for part in (
        clean(profile.get("first_name")), clean(profile.get("last_name"))) if part)
    username = clean(profile.get("username"))
    if not username or not all(char in string.ascii_letters + string.digits + "_" for char in username):
        username = ""
    return ("Nazwa wyświetlana: " + (name or "niedostępna")
            + "\nUsername: " + ("@" + username if username else "brak")
            + "\nTelegram ID: " + str(uid))


def admin_profile_canonical(uid, profile):
    if not admin_profile_is_valid(uid, profile):
        return None
    # Store only a minimum of public-in-Telegram display labels; no chat bodies.
    return {"id": uid, "type": "private", **{
        key: "".join(c for c in profile[key] if c.isprintable()).strip()[:64]
        for key in ("first_name", "last_name", "username")
        if isinstance(profile.get(key), str)}}


def admin_profile_cache_load():
    try:
        path = admin_profile_cache_path()
        fd = os.open(str(path), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as handle:
            content = handle.read(131073)
        if len(content) > 131072:
            return {}
        loaded = json.loads(content)
        if not isinstance(loaded, dict) or loaded.get("version") != 1:
            return {}
        profiles = loaded.get("profiles", {})
        if not isinstance(profiles, dict) or len(profiles) > 500:
            return {}
        return {k: v for k, v in profiles.items() if (
            isinstance(k, str) and k.isdecimal() and admin_profile_is_valid(int(k), v))}
    except (OSError, UnicodeError, ValueError, TypeError, RuntimeError):
        return {}


def admin_profile_cache_save(profiles):
    """Atomic 0600 write; never write profiles to logs or Git."""
    if len(profiles) > 500:
        return False
    try:
        path = admin_profile_cache_path()
        payload = json.dumps(
            {"version": 1, "profiles": profiles}, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        if len(payload) > 131072:
            return False
        temp = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
        fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, path)
            return True
        finally:
            if temp.exists():
                temp.unlink()
    except (OSError, UnicodeError, RuntimeError):
        return False


def admin_profile_lookup(request, token, uid):
    # Fail open for presentation only. RBAC membership always comes from PG.
    try:
        return admin_profile_canonical(uid, request(token, "getChat", {"chat_id": uid}))
    except RuntimeError:
        return None


def show_admins(request, token, owner, viewer, sender, raw, *, refresh=False, message_id=None):
    parts = raw.split()
    if len(parts) > 2 or (len(parts) == 2 and
                          (not parts[1].isdecimal() or int(parts[1]) <= 0)):
        send(request, token, viewer, "Użycie: /admins [numer_strony], np. /admins 2")
        return
    page = int(parts[1]) if len(parts) == 2 else 1
    with connect() as con:
        total = con.execute("SELECT COUNT(*) FROM members").fetchone()[0]
        pages = max(1, (total + ADMINS_PAGE_SIZE - 1) // ADMINS_PAGE_SIZE)
        if page <= pages:
            members = [row[0] for row in con.execute(
                "SELECT uid FROM members ORDER BY uid LIMIT ? OFFSET ?",
                (ADMINS_PAGE_SIZE, (page - 1) * ADMINS_PAGE_SIZE)).fetchall()]
        else:
            members = []
    if page > pages:
        send(request, token, viewer, f"Brak strony {page}. Dostępne: 1–{pages}.")
        return

    profiles = admin_profile_cache_load()
    changed = False
    failed = 0
    owner_profile = profiles.get(str(owner))
    if viewer == owner:
        # A verified private command/callback from owner provides fresh labels.
        current = admin_profile_canonical(owner, {**sender, "type": "private"})
        if current is not None and current != owner_profile:
            owner_profile = current
            profiles[str(owner)] = current
            changed = True
    elif refresh or owner_profile is None:
        # A co-admin's sender data must NEVER be presented as owner identity.
        current = admin_profile_lookup(request, token, owner)
        if current is not None:
            owner_profile = current
            profiles[str(owner)] = current
            changed = True
        else:
            failed += 1
    lines = ["🔐 Administratorzy Browser VPS",
             "\n👑 Właściciel\n" + admin_profile_text(owner, owner_profile),
             f"\n👥 Współadministratorzy ({total})"]
    for member in members:
        cached = profiles.get(str(member))
        if refresh or cached is None:
            updated = admin_profile_lookup(request, token, member)
            if updated is not None:
                cached = updated
                profiles[str(member)] = updated
                changed = True
            else:
                failed += 1
        lines.append("\n👤 " + admin_profile_text(member, cached))
    if changed and not admin_profile_cache_save(profiles):
        lines.append("\n⚠️ Nie udało się zapamiętać nazw na przyszłość.")
    if not total:
        lines.append("brak")
    if refresh and failed:
        lines.append(f"\n⚠️ Nie udało się odświeżyć {failed} profili. Pokazano zapamiętane nazwy lub ID.")
    if pages > 1:
        lines.append(f"\nStrona {page}/{pages}")
    buttons = []
    navigation = []
    if page > 1:
        navigation.append({"text": "⬅️ Poprzednia", "callback_data": f"admin:page:{page-1}"})
    if page < pages:
        navigation.append({"text": "➡️ Następna", "callback_data": f"admin:page:{page+1}"})
    if navigation:
        buttons.append(navigation)
    buttons.append([{"text": "🔄 Odśwież nazwy", "callback_data": f"admin:refresh:{page}"}])
    payload = {"chat_id": viewer, "text": "\n".join(lines),
               "reply_markup": {"inline_keyboard": buttons}}
    if type(message_id) is int and message_id > 0:
        try:
            request(token, "editMessageText", {**payload, "message_id": message_id})
            return
        except RuntimeError:
            pass
    request(token, "sendMessage", payload)


def command_text(update):
    msg = update.get("message")
    if not isinstance(msg,dict):
        return None
    sender, chat = msg.get("from"),msg.get("chat")
    if not isinstance(sender,dict) or not isinstance(chat,dict):
        return None
    uid = sender.get("id")
    if type(uid) is not int or uid <= 0 or chat.get("type") != "private" or chat.get("id") != uid:
        return None
    sent_at = msg.get("date")
    if type(sent_at) is not int or not 0 <= time.time()-sent_at <= 120:
        return None
    raw=msg.get("text","")
    if not isinstance(raw,str) or len(raw)>256:
        return None
    return uid,raw.strip(),sender


def submit_invitation(uid, code, sender, owner, request, token, *, now=None,
                      notify_applicant=True, source="Bot API", invite_id=None, invite_tag=None):
    """Consume one invitation for a verified Telegram principal.

    This is the shared application operation for Bot API /join_admin and the
    separately authenticated Mini App endpoint. It accepts an already
    established Telegram user ID; it never fabricates a Bot API update.
    """
    now = int(time.time()) if now is None else now
    if type(uid) is not int or uid <= 0 or type(owner) is not int or owner <= 0:
        return {"status": "invalid"}
    if uid == owner:
        if notify_applicant:
            send(request, token, uid, "ℹ️ Jesteś właścicielem — nie potrzebujesz zaproszenia.")
        return {"status": "owner"}
    if not isinstance(sender, dict):
        sender = {}
    if is_admin(uid, owner):
        if notify_applicant:
            send(request, token, uid, "✅ Masz już uprawnienia współadministratora.")
        return {"status": "already_admin"}
    if invite_id is not None:
        if (type(invite_id) is not int or not 1 <= invite_id < 2**63
                or not isinstance(invite_tag, str)
                or not re.fullmatch(r"[0-9a-f]{32}", invite_tag)):
            return {"status": "invalid"}
        digest = None
    else:
        if (not isinstance(code, str) or not 10 <= len(code) <= 128
                or not all(c.isalnum() or c in "_-" for c in code)):
            if notify_applicant:
                send(request, token, uid, "❌ Nieprawidłowy format kodu. Sprawdź, czy zaproszenie jest kompletne.")
            trace("failed_code_attempt", uid=uid, detail="invalid_format")
            failed_code_alert(request, token, owner, uid, sender, "błędny format")
            return {"status": "invalid_format"}
        digest = hashlib.sha256(code.encode()).hexdigest()

    accepted = False
    result = "invalid"
    error = "❌ Nieprawidłowe lub nieaktualne zaproszenie. Poproś właściciela o nowy link."
    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        # Recheck membership inside the same transaction as invite consumption.
        if con.execute("SELECT 1 FROM members WHERE uid=?", (uid,)).fetchone():
            result = "already_admin"
        else:
            attempt = con.execute(
                "SELECT count,started FROM attempts WHERE uid=?", (uid,)
            ).fetchone()
            if attempt and now - attempt[1] < TTL and attempt[0] >= 5:
                result = "rate_limited"
                error = "⏳ Przekroczono limit prób (5 na 10 minut). Spróbuj później."
            else:
                count = attempt[0] + 1 if attempt and now - attempt[1] < TTL else 1
                start = attempt[1] if attempt and now - attempt[1] < TTL else now
                con.execute("INSERT OR REPLACE INTO attempts VALUES(?,?,?)", (uid, count, start))
                if invite_id is not None:
                    row = con.execute(
                        "SELECT id,hash,expires,pending_uid,issued_seconds "
                        "FROM invitations WHERE id=?", (invite_id,)
                    ).fetchone()
                else:
                    row = con.execute(
                        "SELECT id,hash,expires,pending_uid,issued_seconds "
                        "FROM invitations WHERE hash=?", (digest,)
                    ).fetchone()
                if row and row[3] is not None:
                    result = "already_pending"
                    error = "⏳ To zaproszenie zostało już zgłoszone. Poczekaj na decyzję właściciela."
                elif row and row[2] and row[2] < now:
                    result = "expired"
                    error = "⌛ Zaproszenie wygasło. Poproś właściciela o nowe."
                elif (row and row[1] and row[2] >= now
                      and (miniapp_invite_locator_matches(
                               invite_id, token, row[1], invite_tag)
                           if invite_id is not None
                           else secrets.compare_digest(row[1], digest))):
                    nonce = secrets.token_urlsafe(12)
                    username = sender.get("username", "")
                    name = ("@" + username if isinstance(username, str)
                            and len(username) < 64
                            and username.replace("_", "").isalnum()
                            else ("Mini App (Telegram)" if source == "Mini App" else "brak nazwy"))
                    consumed = con.execute(
                        "UPDATE invitations SET hash=NULL,pending_uid=?,pending_name=?,"
                        "pending_until=?,nonce=? WHERE id=? AND hash=? AND pending_uid IS NULL",
                        (uid, name, now + (row[4] if row[4] is not None
                                           else max(0, row[2] - now)),
                         nonce, row[0], row[1]),
                    )
                    if consumed.rowcount == 1:
                        accepted = True
                        result = "pending_owner_approval"
                        trace("join_accepted", row[0], uid)

    if accepted:
        # Preserve existing ordering: owner alert first, then applicant notice.
        trace("owner_alert_attempt", row[0], uid)
        try:
            decision_until = now + (row[4] if row[4] is not None
                                    else max(0, row[2] - now))
            send(
                request, token, owner,
                "🚨 NOWE ZGŁOSZENIE — WYMAGA TWOJEJ WERYFIKACJI!\n\n" +
                ("✅ Użytkownik potwierdził konto przez Telegram Mini App.\n"
                 if source == "Mini App" else "✅ Użytkownik przesłał kod przez /join_admin.\n") +
                "🆔 Telegram ID: " + str(uid) + "\n\n"
                "⏳ Czeka na Twoją decyzję. Samo zgłoszenie nie nadaje dostępu.\n"
                "Na zatwierdzenie: " +
                (duration_label(row[4]) if row[4] is not None
                 else "według dotychczasowego terminu") +
                "\nTermin decyzji: " + expiry_time(decision_until) +
                "\nDane kodu:" + time_details(row[2], row[4]) +
                "\nMożesz też użyć /pending_admins.",
                [[{"text": "✅ Zatwierdź", "callback_data": "admin:approve:" + nonce},
                  {"text": "❌ Odrzuć", "callback_data": "admin:reject:" + nonce}]],
            )
        except Exception:
            trace("owner_alert_failed", row[0], uid)
            raise
        trace("owner_alert_sent", row[0], uid)
        if notify_applicant:
            send(request, token, uid,
                 "✅ Zaproszenie przyjęte. Właściciel otrzymał zgłoszenie. "
                 "Dostęp zostanie nadany dopiero po jego zatwierdzeniu.\n"
                 "Termin decyzji: " + expiry_time(decision_until))
    else:
        if notify_applicant:
            send(request, token, uid, error)
        if result not in ("already_admin", "owner"):
            trace("join_rejected", uid=uid, detail=(
                "rate_limited" if result == "rate_limited"
                else "expired" if result == "expired" else "invalid"))
            failed_code_alert(request, token, owner, uid, sender,
                              "odrzucona próba weryfikacji zaproszenia")
    return {"status": result}

def handle(token, owner, update, request):
    """Returns True if an invitation-related command/callback was handled."""
    if not isinstance(update,dict):
        return False
    callback=update.get("callback_query")
    if isinstance(callback,dict) and isinstance(callback.get("data"),str) and callback["data"].startswith("admin:"):
        who=callback.get("from")
        msg=callback.get("message")
        chat=msg.get("chat") if isinstance(msg,dict) else None
        caller = who.get("id") if isinstance(who, dict) else None
        if (type(caller) is not int or caller <= 0 or not isinstance(chat,dict)
                or chat.get("type") != "private" or chat.get("id") != caller):
            return True
        parts=callback["data"].split(":")
        outcome="Zgłoszenie zostało już rozpatrzone albo zaproszenie jest nieważne."
        decision_status=None
        if (len(parts) == 3 and parts[1] in ("page", "refresh")
                and parts[2].isdecimal() and 0 < int(parts[2]) <= 100000):
            # Recheck live PostgreSQL role on every callback; revoked users
            # cannot use old refresh/page buttons to read the list.
            if caller != owner and not is_admin(caller, owner):
                return True
            show_admins(request, token, owner, caller, who, "/admins " + parts[2],
                        refresh=(parts[1] == "refresh"), message_id=msg.get("message_id"))
            try:
                request(token, "answerCallbackQuery", {"callback_query_id": callback.get("id")})
            except RuntimeError:
                pass
            return True
        # Every other admin:* action, including approvals and rotations, stays
        # owner-only even for authorized co-admins.
        if caller != owner:
            return True
        if len(parts)==3 and parts[1]=="rotate" and parts[2].isdecimal():
            rotate_invite(token,owner,request,int(parts[2]),int(time.time()))
            try:request(token,"answerCallbackQuery",{"callback_query_id":callback.get("id")})
            except RuntimeError:pass
            return True
        if len(parts)==3 and parts[1] in ("approve","reject") and 12 <= len(parts[2]) <= 128:
            outcome, notice, terminal = decide_invitation(owner,parts[1],parts[2],int(time.time()))
            decision_status = outcome if terminal else None
            if notice:
                uid, decision, _ = notice
                text = ("✅ Twoje zgłoszenie zostało zatwierdzone przez właściciela. Masz teraz dostęp jako współadministrator Browser VPS. Wpisz /help, aby sprawdzić dostępne funkcje."
                        if decision == "approve" else
                        "❌ Właściciel odrzucił Twoje zgłoszenie o dostęp współadministratora Browser VPS. Uprawnienia nie zostały przyznane.")
                try:
                    send(request,token,uid,text)
                except RuntimeError:
                    print("COADMIN_DECISION_NOTICE_FAILED",flush=True)
        # Bot API 10.3: a real disabled inline button can display the result.
        # The database transaction above, never the button, controls permissions.
        if len(parts)==3 and parts[1] in ("approve","reject") and 12 <= len(parts[2]) <= 128:
            message_id=msg.get("message_id")
            if type(message_id) is int and message_id > 0 and decision_status:
                try:
                    reply=request(token,"editMessageReplyMarkup",{
                        "chat_id":owner,"message_id":message_id,
                        "reply_markup":{"inline_keyboard":[[{
                            "text":decision_status,"disabled":{}
                        }]]}})
                    if reply is False:
                        raise RuntimeError("STATUS_MARKUP_NOT_CONFIRMED")
                except RuntimeError:
                    # Older Bot API endpoints may not support disabled buttons.
                    # Remove active actions rather than leave a repeatable choice.
                    print("COADMIN_DECISION_STATUS_MARKUP_FAILED",flush=True)
                    try:
                        request(token,"editMessageReplyMarkup",{
                            "chat_id":owner,"message_id":message_id,
                            "reply_markup":{"inline_keyboard":[]}})
                    except RuntimeError:
                        print("COADMIN_DECISION_MARKUP_FAILED",flush=True)
                    try:
                        send(request,token,owner,outcome)
                    except RuntimeError:
                        print("COADMIN_DECISION_NOTICE_FAILED",flush=True)
        try:
            request(token,"answerCallbackQuery",{
                "callback_query_id":callback.get("id"),"text":outcome[:170],
                "show_alert":bool(decision_status is None)})
        except RuntimeError:pass
        return True
    parsed=command_text(update)
    if not parsed:return False
    uid,raw,sender=parsed
    action=raw.split(maxsplit=1)[0].split("@")[0].lower() if raw else ""
    if action not in ("/invite_admin","/join_admin","/admins","/remove_admin","/cancel_invite","/pending_admins","/invite_history","/regenerate_invite"):
        return False
    if uid != owner and (action not in ("/join_admin", "/admins")
                         or (action == "/admins" and not is_admin(uid, owner))):
        send(request,token,uid,"⛔ Odmowa dostępu.")
        return True
    now=int(time.time())
    if action=="/invite_history":
        with connect() as con:
            rows=con.execute("SELECT invite_id,action,subject_id,at FROM invite_history ORDER BY id DESC LIMIT 20").fetchall()
        lines=["📜 Historia zaproszeń (ostatnie 20 zdarzeń):"]
        lines.extend(f"#{i} — {a} — ID {u or '-'} — {time.strftime('%Y-%m-%d %H:%M',time.localtime(t))}" for i,a,u,t in rows)
        send(request,token,owner,"\n".join(lines) if rows else "📭 Historia zaproszeń jest pusta.")
        return True
    if action=="/regenerate_invite":
        parts=raw.split()
        if len(parts)!=2 or not parts[1].isdecimal():
            send(request,token,owner,"Użycie: /regenerate_invite ID")
        else:
            rotate_invite(token,owner,request,int(parts[1]),now)
        return True
    if action=="/pending_admins":
        show_pending(token,owner,request,now)
        return True
    if action=="/invite_admin":
        duration=parse_duration(raw)
        if duration is None:
            send(request,token,owner,"Użycie: /invite_admin [czas], np. /invite_admin 30h. Zakres: 1m–72h.")
            return True
        ttl, label=duration
        code=generate_invite_code()
        with connect() as con:
            con.execute("BEGIN IMMEDIATE")
            active=con.execute("SELECT COUNT(*) FROM invitations WHERE expires>=?",(now,)).fetchone()[0]
            if active>=30:
                con.execute("ROLLBACK")
                send(request,token,owner,"Limit 30 aktywnych zaproszeń. Poczekaj na wygaśnięcie lub anuluj.")
                return True
            con.execute("INSERT INTO invitations(hash,expires,pending_uid,pending_name,pending_until,nonce) VALUES(?,?,?,?,?,?)",
                (hashlib.sha256(code.encode()).hexdigest(),now+ttl,None,None,None,None))
            ident=con.execute("SELECT last_insert_rowid()").fetchone()[0]
            con.execute("UPDATE invitations SET created_at=?,issued_seconds=? WHERE id=?",(now,ttl,ident))
            audit(con,ident,"created",owner)
        send(request,token,owner,invitation_message(code,now+ttl,ttl,ident,False,miniapp_invite_url(request,token,ident,new)))
    elif action=="/cancel_invite":
        parts=raw.split()
        if len(parts)!=2 or not parts[1].isdecimal():
            send(request,token,owner,"Użycie: /cancel_invite ID (anulowanie jednego zaproszenia).")
        else:
            ident=int(parts[1])
            with connect() as con:
                con.execute("BEGIN IMMEDIATE")
                row=con.execute("SELECT pending_uid FROM invitations WHERE id=? AND expires>=?",(ident,now)).fetchone()
                if row:
                    audit(con,ident,"cancelled",owner,row[0])
                    con.execute("DELETE FROM invitations WHERE id=?",(ident,))
            send(request,token,owner,f"✅ Zaproszenie #{ident} anulowane." if row else "Nie znaleziono aktywnego zaproszenia.")
    elif action=="/join_admin":
        parts=raw.split()
        if len(parts)!=2:
            send(request,token,uid,"ℹ️ Użycie: /join_admin KOD\nWklej cały kod otrzymany od właściciela.")
            failed_code_alert(request,token,owner,uid,sender,"brak kodu")
            return True
        submit_invitation(uid,parts[1],sender,owner,request,token,now=now)
    elif action=="/admins":
        show_admins(request, token, owner, uid, sender, raw)
    elif action=="/remove_admin":
        part=raw.split()
        target=int(part[1]) if len(part)==2 and part[1].isdecimal() else None
        if not target or target==owner:
            send(request,token,owner,"⛔ Konta właściciela nie można usunąć. Użycie: /remove_admin ID")
        else:
            with connect() as con:con.execute("DELETE FROM members WHERE uid=?",(target,))
            cached = admin_profile_cache_load()
            if cached.pop(str(target), None) is not None:
                admin_profile_cache_save(cached)
            send(request,token,owner,"Cofnięto dostęp ID: "+str(target))
    return True

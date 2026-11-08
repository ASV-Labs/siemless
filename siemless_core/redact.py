"""Redaction and bounding for anything siemless writes to disk or sends anywhere.

Adapted from lineage (ASV Labs, MIT; github.com/P0GL0L/hermes-lineage, lineage_core/redact.py at
14ae9e9) — same author, same policy. siemless records *that* a tool ran and *what it touched*, not what it said. Tool
arguments and results are reduced to bounded previews, and anything that looks
like a credential is replaced before the bytes reach SQLite. The patterns here
are deliberately broad: siemless prefers to redact a harmless string over storing
a secret, and nothing downstream (events, findings, exporters, Desktop page) needs the
original text.
"""

from __future__ import annotations

import re
from typing import Any

MASK = "«redacted»"

# Vendor prefixes are assembled from parts so a scanner that greps this file for
# credential shapes does not mistake the detector for a leaked credential.
_PREFIXES = [
    "sk" + "-ant-",
    "sk" + "-",
    "gh" + "p_",
    "gh" + "o_",
    "gh" + "u_",
    "gh" + "s_",
    "gh" + "r_",
    "github" + "_pat_",
    "gl" + "pat-",
    "xox" + "b-",
    "xox" + "p-",
    "xox" + "a-",
    "AK" + "IA",
    "AI" + "za",
    "np" + "m_",
    "py" + "pi-",
    "hf" + "_",
    "r8" + "_",
    "fal" + "_",
    "sb" + "p_",
    "shp" + "at_",
    "sq0" + "atp-",
    "sk" + "_live_",   # Stripe secret / restricted keys (underscore, unlike OpenAI's hyphen)
    "sk" + "_test_",
    "rk" + "_live_",
    "rk" + "_test_",
    "AS" + "IA",       # AWS STS temporary access key id
    "SG" + ".",        # SendGrid
    "dop" + "_v1_",    # DigitalOcean personal / OAuth / refresh tokens
    "doo" + "_v1_",
    "dor" + "_v1_",
    "gl" + "sa_",      # Grafana service account
    "gl" + "c_",       # Grafana cloud
    "lin" + "_api_",   # Linear
    "xa" + "pp-",      # Slack app-level token
    "AGE-SECRET" + "-KEY-",
    "ATAT" + "T3",     # Atlassian API token
    "nf" + "p_",       # Netlify
    "pn" + "u_",       # Pulumi
    "ey" + "J",  # JWT header start (base64 of '{"')
]

# Unlike lineage, a credential-shaped token *inside a path* (``/tmp/ghp_…/notes.txt``) is masked too: SIEMless
# exports off the machine, so a false positive on an odd directory name costs less than a leak.
_PREFIX_RE = re.compile(
    r"(?<![A-Za-z0-9_+-])(?:" + "|".join(re.escape(p) for p in _PREFIXES) + r")[A-Za-z0-9_\-.+=]{16,}"
)

# key = value / key: value / "key": "value" with a credential-looking key name.
_KV_RE = re.compile(
    # (?<![A-Za-z0-9]) rather than \b: npm's ``//registry/:_authToken=`` and ``:_password=`` put an
    # underscore (a word character) right before the key.
    r"(?i)((?<![A-Za-z0-9])(?:api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key(?:[_-]?id)?|"
    r"auth[_-]?token|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|npm[_-]?token|"
    r"token|secret|password|passwd|pwd|credential|authorization|cookie|set-cookie|_auth)"
    r"[\"']?\s*[:=]\s*)(\"[^\"\n]+\"|'[^'\n]+'|[^\s\"',;&]{6,})"
)

_BEARER_RE = re.compile(r"(?i)\b(bearer|basic|token)\s+([A-Za-z0-9_\-./+=]{12,})")
# A key block is masked to its END marker, or to the end of the text when the END marker was cut off.
_PEM_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
    re.DOTALL,
)

# Credentials passed as command-line flags.
#   curl -u user:pass / --user user:pass / --proxy-user u:p
_CLI_USERPASS_RE = re.compile(r"((?:^|\s)(?:-u|--user|--proxy-user|-U)(?:\s+|=)?(['\"]?)[^\s:'\"]*:)([^\s'\"]+)(\2)")
#   --password X, --password=X, --api-key X, --token=X, --client-secret X, --auth-token X ...
_CLI_SECRET_FLAG_RE = re.compile(
    r"(?i)((?:^|\s)--?[a-z0-9-]*(?:password|passwd|passphrase|token|secret|api-?key|access-?key|private-?key|credentials?)"
    r"[a-z0-9-]*(?:\s+|=))(['\"]?)((?!-)[^\s'\"]+)(\2)")
#   mysql -uroot -pPASS (password glued to -p), sshpass -p PASS
_MYSQL_P_RE = re.compile(r"(\b(?:mysql|mysqldump|mysqladmin|mysqlsh|mariadb|mariadb-dump|mysqlimport)\b[^|;&\n]*?\s-p)(['\"]?)([^\s'\"]+)(\2)")
_REDIS_PASS_RE = re.compile(r"(\b(?:redis-cli|valkey-cli|keydb-cli)\b[^|;&\n]*?\s(?:-a|--pass|--password)\s+)(['\"]?)([^\s'\"]+)(\2)")
# .netrc lines separate key and value with whitespace: ``machine h login u password p``.
_NETRC_RE = re.compile(r"(?i)(\b(?:machine|login|account|default)\b[^\n]{0,200}?\b(?:password|passwd)\s+)(['\"]?)([^\s'\"]+)(\2)")
_SSHPASS_RE = re.compile(r"(\bsshpass\s+-p\s*)(['\"]?)([^\s'\"]+)(\2)")
# Webhook URLs carry their credential in the path.
_WEBHOOK_PATH_RE = re.compile(
    r"(?i)((?:hooks\.slack\.com/(?:services|workflows|triggers)/)|"
    r"(?:(?:discord(?:app)?\.com|ptb\.discord\.com|canary\.discord\.com)/api/(?:v\d+/)?webhooks/\d+/)|"
    r"(?:\.webhook\.office\.com/webhookb2/)|(?:/hooks/[a-z0-9]{0,8}/?))([A-Za-z0-9_\-/@.]{8,})")
# user:password@ (or :password@ with no user) in any scheme (https, postgres, redis, amqp, ftp, …)
_URL_CRED_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]*):([^/\s@]+)@")
# Query parameters whose *name* says credential. Names are split into words (``X-Amz-Signature`` →
# x, amz, signature; ``accessToken`` → access, token) and matched word by word, so ``author``,
# ``keyword`` and ``zipcode`` are left alone while ``client_secret`` and ``apiKey`` are masked.
# Unambiguous fragments: masked wherever they occur in the joined name (authtoken, secretkey, apiKey2).
_SECRET_FRAGMENTS = ("token", "secret", "password", "passwd", "apikey", "signature", "credential",
                     "accesskey", "privatekey", "sessionid", "sessiontoken", "clientsecret")
# Short words that are secrets only as a whole word (digits ignored): api_key, x-api-key, key2, sig, auth.
_PAGINATION = ("pagetoken", "nexttoken", "continuationtoken", "cursortoken", "pagingtoken", "synctoken")
_SECRET_WORDS = frozenset({"key", "sig", "pwd", "pass", "auth", "jwt", "otp", "hmac", "sid", "session"})
_QUERY_PARAM_RE = re.compile(r"([?&])([^=&#\s\"'`]+)=([^&#\s\"'`]*)")


def _name_words(name: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(name))
    return [w for w in re.split(r"[\s_.\-\[\]]+", spaced.lower()) if w]


def is_secret_param_name(name: str) -> bool:
    """``client_secret``, ``X-Amz-Signature``, ``authtoken``, ``apiKey2``, ``code`` (OAuth) → True;
    ``author``, ``keyword``, ``zipcode``, ``country_code``, ``promo_code`` → False."""
    words = [w.rstrip("0123456789") for w in _name_words(name)]
    joined = "".join(words)
    if any(f in joined for f in _PAGINATION):
        return False  # page_token, nextPageToken, continuation_token: a cursor, not a credential
    if any(f in joined for f in _SECRET_FRAGMENTS):
        return True
    if any(w in _SECRET_WORDS for w in words):
        return True
    # "code" only as the OAuth authorization code itself
    return words in (["code"], ["auth", "code"], ["authorization", "code"])


def mask_query_secrets(query_or_text: str, mask: str = "«redacted»") -> str:
    """Mask the values of credential-named query parameters wherever ``?name=`` / ``&name=`` appears."""
    def sub(m: re.Match) -> str:
        return f"{m.group(1)}{m.group(2)}={mask}" if m.group(3) and is_secret_param_name(m.group(2)) else m.group(0)

    return _QUERY_PARAM_RE.sub(sub, query_or_text)


# Tokens carried in a URL path, e.g. Telegram's https://api.telegram.org/bot<id>:<secret>/getUpdates
_PATH_TOKEN_RE = re.compile(r"(/bot|(?<![A-Za-z0-9]))(\d{6,}:[A-Za-z0-9_-]{30,})")

# Env-var style assignments inside shell commands: FOO_TOKEN=abc, export X_KEY="..."
_ENV_ASSIGN_RE = re.compile(
    r"(?i)\b([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS(?![A-Z])|PWD|AUTH(?![A-Z])|CREDENTIALS?)[A-Z0-9_]*\s*=\s*)([\"']?)([^\s\"']{4,})(\2)"
)

# Argument names are compared with case, '_' and '-' removed, so accessToken, access_token and
# Access-Token are the same name.
_SECRET_ARG_EXACT = frozenset({"auth", "headers", "cookie", "cookies", "pwd", "pin", "otp", "dsn"})
_SECRET_ARG_PARTS = ("token", "secret", "password", "passwd", "apikey", "accesskey", "privatekey",
                     "authorization", "credential", "signature", "cookie", "sessionid", "connectionstring")


def is_secret_arg_name(name: str) -> bool:
    k = re.sub(r"[_\-\s]", "", str(name)).lower()
    return k in _SECRET_ARG_EXACT or any(part in k for part in _SECRET_ARG_PARTS)


def _kv_sub(m: re.Match) -> str:
    v = m.group(2)
    q = v[0] if v[:1] in ("\"", "'") else ""
    return f"{m.group(1)}{q}{MASK}{q}"


def redact_text(text: str) -> str:
    """Return *text* with credential-shaped substrings masked."""
    if not text:
        return text
    out = _PEM_RE.sub(MASK, text)
    out = _URL_CRED_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}:{MASK}@", out)
    out = _WEBHOOK_PATH_RE.sub(lambda m: f"{m.group(1)}{MASK}", out)
    out = _CLI_USERPASS_RE.sub(lambda m: f"{m.group(1)}{MASK}{m.group(4)}", out)
    out = _MYSQL_P_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}{m.group(4)}", out)
    out = _SSHPASS_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}{m.group(4)}", out)
    out = _REDIS_PASS_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}{m.group(4)}", out)
    out = _NETRC_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}{m.group(4)}", out)
    out = _CLI_SECRET_FLAG_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}{m.group(4)}", out)
    out = mask_query_secrets(out, MASK)
    out = _PATH_TOKEN_RE.sub(lambda m: f"{m.group(1) or ''}{MASK}", out)
    out = _ENV_ASSIGN_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}{m.group(4)}", out)
    out = _BEARER_RE.sub(lambda m: f"{m.group(1)} {MASK}", out)
    out = _KV_RE.sub(_kv_sub, out)
    out = _PREFIX_RE.sub(MASK, out)
    return out


def preview(text: Any, limit: int = 240) -> str:
    """A short, redacted, single-line preview of *text*."""
    if text is None:
        return ""
    if not isinstance(text, str):
        try:
            text = str(text)
        except Exception:
            return ""
    # Redact only what can end up in the preview: a 1 MB argument must not cost the agent thread a
    # regex pass over 1 MB (measured: ~120 ms). A secret straddling the cut is masked by the prefix
    # patterns on whichever side keeps its start; the tail is dropped anyway.
    cut = limit * 8
    if len(text) > cut:
        # Keep an overlap so a secret straddling the cut still matches its pattern, then drop the
        # trailing partial token so no secret head survives. A PEM block whose END line lies beyond
        # the overlap is still masked: _PEM_RE runs to END *or* the end of the slice.
        head = redact_text(text[: cut + 512])[:cut]
        sp = max(head.rfind(" "), head.rfind("\n"), head.rfind("\t"))
        text = head[:sp] if sp > 0 else ""
    else:
        text = redact_text(text)
    text = " ".join(text.split())
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def bound_args(args: Any, *, per_value: int = 400, total: int = 4000, depth: int = 0) -> Any:
    """Return a JSON-safe, redacted, size-bounded copy of tool arguments.

    Long string values become ``{"$preview": ..., "$chars": n}`` so the shape of the call survives
    without its payload. *total* is one budget shared by every value at every depth (dicts and lists
    alike); when it runs out the rest is replaced by ``"$truncated": true``. Keys are redacted too.
    """
    budget = [int(total)]
    return _bound(args, per_value, budget, depth)


def _bound(args: Any, per_value: int, budget: list, depth: int) -> Any:
    if budget[0] <= 0:
        return {"$truncated": True}
    if depth > 6:
        return "…"
    if isinstance(args, dict):
        out: dict[str, Any] = {}
        for key, value in list(args.items())[:64]:
            k = redact_text(str(key))[:100]
            budget[0] -= len(k) + 4
            if is_secret_arg_name(str(key)):
                out[k] = MASK
                continue
            if budget[0] <= 0:
                out["$truncated"] = True
                break
            out[k] = _bound(value, per_value, budget, depth + 1)
        if len(args) > 64:
            out["$more"] = len(args) - 64
        return out
    if isinstance(args, (list, tuple)):
        items = []
        for v in list(args)[:32]:
            if budget[0] <= 0:
                items.append({"$truncated": True})
                break
            items.append(_bound(v, per_value, budget, depth + 1))
        if len(args) > 32:
            items.append({"$more": len(args) - 32})
        return items
    if isinstance(args, str):
        if len(args) > per_value:
            out_s = {"$preview": preview(args, per_value), "$chars": len(args)}
            budget[0] -= per_value + 24
            return out_s
        red = redact_text(args)
        budget[0] -= len(red) + 2
        return red
    if isinstance(args, (int, float, bool)) or args is None:
        budget[0] -= 8
        return args
    pv = preview(args, per_value)
    budget[0] -= len(pv) + 2
    return pv


__all__ = ["MASK", "is_secret_param_name", "mask_query_secrets", "redact_text", "preview", "bound_args", "is_secret_arg_name"]

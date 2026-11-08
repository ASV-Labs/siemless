"""Classifiers that turn tool arguments into security facts.

All functions here are pure, deterministic and cheap: they look at paths, URLs and command
strings and answer *what was targeted*. They never read the filesystem or the network. Every
answer they give is an **inference from arguments**; the caller labels the event accordingly.
"""

from __future__ import annotations

import os
import re
import shlex
from typing import Iterable, Optional
from urllib.parse import urlsplit

# ----------------------------------------------------------------------------- sensitive paths
# Each entry: (regex on the normalised path, tag). The tag names the kind of credential store so a
# rule can say "ssh key" or "cloud credentials" rather than "sensitive file".
_SENSITIVE_PATHS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(^|/)\.ssh(/|$)"), "ssh"),
    (re.compile(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$"), "ssh"),
    (re.compile(r"\.(pem|key|p12|pfx|jks|keystore|ppk)$", re.I), "private_key"),
    (re.compile(r"(^|/)\.hermes/(profiles/[^/]+/)?(\.env|auth\.json|credentials)", re.I), "hermes_secrets"),
    (re.compile(r"(^|/)\.env(\.[A-Za-z0-9_.-]+)?$"), "dotenv"),
    (re.compile(r"(^|/)auth\.json$"), "hermes_secrets"),
    (re.compile(r"(^|/)\.aws(/|$)"), "cloud"),
    (re.compile(r"(^|/)\.(gcloud|config/gcloud|azure|oci|kube)(/|$)"), "cloud"),
    (re.compile(r"(^|/)kubeconfig$|(^|/)\.kube/config$"), "cloud"),
    (re.compile(r"(^|/)\.netrc$|(^|/)_netrc$"), "netrc"),
    (re.compile(r"(^|/)\.(npmrc|pypirc|yarnrc|cargo/credentials(\.toml)?|gem/credentials)$"), "package_registry"),
    (re.compile(r"(^|/)\.docker/config\.json$"), "docker"),
    (re.compile(r"(^|/)\.git-credentials$"), "git"),
    (re.compile(r"(^|/)\.gnupg(/|$)"), "gpg"),
    (re.compile(r"(^|/)(Login Data|Cookies|Web Data|Local State|logins\.json|key4\.db|cookies\.sqlite)$"), "browser"),
    (re.compile(r"(^|/)Library/Keychains(/|$)|(^|/)login\.keychain(-db)?$"), "keychain"),
    (re.compile(r"(^|/)wallet\.dat$|(^|/)\.(bitcoin|ethereum|electrum)(/|$)"), "wallet"),
    (re.compile(r"(^|/)\.(bash|zsh|fish)_history$|(^|/)\.history$"), "shell_history"),
    (re.compile(r"(^|/)\.(password-store|pass)(/|$)"), "password_store"),
    (re.compile(r"(^|/)(secrets?|credentials?|tokens?)\.(json|ya?ml|toml|txt|ini|env)$", re.I), "secrets_file"),
    (re.compile(r"(^|/)\.terraform(/|$)|(^|/)terraform\.tfstate"), "iac_state"),
    (re.compile(r"(^|/)\.config/(gh|hub|op|1Password)(/|$)"), "cli_tokens"),
    (re.compile(r"(^|/)\.ssh/authorized_keys$"), "ssh"),
    (re.compile(r"/etc/(shadow|gshadow|sudoers|master\.passwd)$"), "system_auth"),
]

# Files whose edit changes how the agent is governed. Tag names the control.
_SECURITY_CONFIG_PATHS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(^|/)\.hermes/(profiles/[^/]+/)?config\.ya?ml$"), "hermes_config"),
    (re.compile(r"(^|/)\.hermes/(profiles/[^/]+/)?\.env$"), "hermes_env"),
    (re.compile(r"(^|/)\.hermes/(profiles/[^/]+/)?(SOUL|AGENTS|USER|MEMORY)\.md$", re.I), "agent_instructions"),
    (re.compile(r"(^|/)\.hermes/(profiles/[^/]+/)?hooks(/|$)"), "hermes_hooks"),
    (re.compile(r"(^|/)\.hermes/(profiles/[^/]+/)?plugins(/|$)"), "hermes_plugins"),
    (re.compile(r"(^|/)\.hermes/(profiles/[^/]+/)?desktop-plugins(/|$)"), "hermes_plugins"),
    (re.compile(r"(^|/)\.hermes/(profiles/[^/]+/)?skills(/|$)"), "hermes_skills"),
    (re.compile(r"(^|/)\.hermes/(profiles/[^/]+/)?cron(/|$)"), "hermes_cron"),
    (re.compile(r"(^|/)(AGENTS|CLAUDE|SOUL)\.md$"), "agent_instructions"),
    (re.compile(r"(^|/)\.claude/(settings(\.local)?\.json|hooks)"), "agent_instructions"),
    (re.compile(r"(^|/)\.(cursorrules|windsurfrules|github/copilot-instructions\.md)$"), "agent_instructions"),
    (re.compile(r"(^|/)(crontab|cron\.d|cron\.daily|LaunchAgents|LaunchDaemons|systemd/user)(/|$)"), "os_persistence"),
    (re.compile(r"(^|/)\.(bashrc|zshrc|profile|bash_profile|zprofile|config/fish/config\.fish)$"), "shell_rc"),
    (re.compile(r"(^|/)\.ssh/(config|authorized_keys)$"), "ssh_config"),
    (re.compile(r"/etc/(hosts|sudoers|pam\.d|ssh/sshd_config|resolv\.conf)"), "system_config"),
]


def _norm_path(path: str) -> str:
    p = str(path).strip().strip("'\"")
    p = p.replace("\\", "/")
    p = re.sub(r"^~", "/home/~", p)  # keep '~' recognisable without expanding the real home
    p = re.sub(r"^\$HOME", "/home/~", p)
    return p


def classify_path(path: Optional[str]) -> list[str]:
    """Tags for *path*: ``sensitive:<kind>`` for credential stores, ``config:<kind>`` for governance
    files. Empty when the path is ordinary."""
    if not path:
        return []
    p = _norm_path(path)
    tags: list[str] = []
    for rx, tag in _SENSITIVE_PATHS:
        if rx.search(p):
            tags.append(f"sensitive:{tag}")
            break
    for rx, tag in _SECURITY_CONFIG_PATHS:
        if rx.search(p):
            tags.append(f"config:{tag}")
            break
    return tags


def paths_in_text(text: str) -> list[str]:
    """Path-like tokens in a command string (absolute, ~-relative, or dotfile-relative)."""
    if not text:
        return []
    out: list[str] = []
    for tok in _tokens(text):
        t = tok.strip("'\"`;,()")
        if not t or t.startswith("-"):
            continue
        if t.startswith(("/", "~", "$HOME", "./", "../")) or t.startswith("."):
            out.append(t)
        elif "/" in t and not t.startswith(("http://", "https://")):
            out.append(t)
    return out[:64]


def _tokens(text: str) -> list[str]:
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()


# --------------------------------------------------------------------------- network clients
_NET_CLIENTS = {
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "rsync", "ftp", "telnet",
    "http", "https", "httpie", "xh", "aria2c", "openssl", "nmap", "dig", "nslookup", "whois", "gh", "git",
    "aws", "gcloud", "az", "kubectl", "docker", "pip", "pip3", "npm", "npx", "pnpm", "yarn", "uv", "cargo",
    "python", "python3", "node", "deno", "bun", "ruby", "perl", "php", "mail", "sendmail", "msmtp", "mutt",
}
_URL_RE = re.compile(r"""(?i)\b((?:https?|ftp|sftp|ssh|smtp|smtps|wss?|git|rsync)://[^\s'"`<>|;)]+)""")
_DEV_TCP_RE = re.compile(r"/dev/(tcp|udp)/([^/\s]+)/(\d+)")

WEBHOOK_HOSTS = (
    "discord.com", "discordapp.com", "hooks.slack.com", "api.telegram.org", "webhook.site", "requestbin.com",
    "pipedream.net", "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "pastebin.com", "paste.ee",
    "transfer.sh", "file.io", "0x0.st", "ix.io", "termbin.com", "hastebin.com", "ghostbin.com", "dpaste.org",
    "interact.sh", "oast.fun", "oastify.com", "burpcollaborator.net", "canarytokens.com", "pipedream.com",
    "zapier.com", "make.com", "n8n.cloud", "ifttt.com", "requestcatcher.com", "beeceptor.com", "mockbin.org",
)
# Egress through these is routine and tagged "egress:dev", so a rule can treat it as lower risk.
DEV_HOSTS = (
    "github.com", "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "gitlab.com",
    "pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "crates.io", "static.crates.io", "deb.debian.org",
    "archive.ubuntu.com", "security.ubuntu.com", "dl.google.com", "download.docker.com", "registry-1.docker.io",
    "huggingface.co", "cdn-lfs.huggingface.co", "astral.sh", "nodejs.org", "golang.org", "proxy.golang.org",
    "rubygems.org", "packagist.org", "homebrew.bintray.com", "formulae.brew.sh", "ghcr.io",
)


def host_of(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    try:
        parts = urlsplit(url if "://" in url else "//" + url)
        return (parts.hostname or "").lower() or None
    except ValueError:
        return None


def classify_host(host: Optional[str]) -> list[str]:
    if not host:
        return []
    h = host.lower()
    tags: list[str] = []
    if any(h == w or h.endswith("." + w) for w in WEBHOOK_HOSTS):
        tags.append("egress:webhook")
    if any(h == d or h.endswith("." + d) for d in DEV_HOSTS):
        tags.append("egress:dev")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h):
        tags.append("egress:raw_ip")
        if h.startswith(("10.", "192.168.", "127.")) or re.match(r"172\.(1[6-9]|2\d|3[01])\.", h):
            tags.append("egress:private")
    if h in ("localhost",) or h.endswith(".local") or h.endswith(".localhost"):
        tags.append("egress:private")
    return tags


def egress_from_command(cmd: str) -> list[dict]:
    """Network destinations a shell command would reach. Each item: {host, port, url, client}.

    Only the command *text* is visible, so this is always an inference: the client might fail,
    the URL might be in a heredoc comment. Rules treat it as "the agent asked the shell to reach X".
    """
    if not cmd:
        return []
    found: dict[str, dict] = {}
    for m in _URL_RE.finditer(cmd):
        url = m.group(1).rstrip(".,")
        h = host_of(url)
        if h:
            found.setdefault(h, {"host": h, "url": url, "port": None, "client": _client_of(cmd)})
    for m in _DEV_TCP_RE.finditer(cmd):
        found.setdefault(m.group(2).lower(), {"host": m.group(2).lower(), "port": int(m.group(3)), "url": None, "client": "bash:/dev/" + m.group(1)})
    toks = _tokens(cmd)
    for i, tok in enumerate(toks):
        base = os.path.basename(tok)
        if base in ("ssh", "nc", "ncat", "netcat", "telnet"):
            skip = False
            for nxt in toks[i + 1:i + 12]:
                if skip:
                    skip = False
                    continue
                if nxt.startswith("-"):
                    skip = nxt in _SSH_ARG_FLAGS
                    continue
                if "://" in nxt:
                    continue
                h = _plausible_host(nxt.split("@")[-1].split(":")[0])
                if h:
                    found.setdefault(h, {"host": h, "url": None, "port": _port_after(toks, i), "client": base})
                break
        elif base in ("scp", "sftp", "rsync"):
            for nxt in toks[i + 1:i + 8]:
                if nxt.startswith("-") or "://" in nxt or ":" not in nxt:
                    continue
                h = _plausible_host(nxt.split(":")[0].split("@")[-1])
                if h:
                    found.setdefault(h, {"host": h, "url": None, "port": None, "client": base})
        elif base == "openssl" and "s_client" in toks[i:i + 3]:
            for j, nxt in enumerate(toks[i:]):
                if nxt in ("-connect",) and j + 1 < len(toks) - i:
                    hp = toks[i + j + 1]
                    h = _plausible_host(hp.split(":")[0])
                    if h:
                        found.setdefault(h, {"host": h, "url": None, "port": _int(hp.split(":")[-1]), "client": base})
    return list(found.values())


_SSH_ARG_FLAGS = {"-p", "-i", "-l", "-o", "-J", "-F", "-L", "-R", "-D", "-W", "-b", "-c", "-e", "-m", "-E", "-Q", "-S", "-B", "-I", "-O", "-P", "-w", "-s", "-X", "-u", "-G"}

_FILE_EXT = {"json", "txt", "py", "sh", "md", "yaml", "yml", "csv", "log", "zip", "tar", "gz", "pem", "key", "env",
             "js", "ts", "html", "css", "png", "jpg", "pdf", "db", "sqlite", "toml", "ini", "cfg", "conf", "lock",
             "tgz", "xz", "bz2", "whl", "jar", "class", "so", "dylib", "exe", "bak", "tmp", "old", "orig"}


def _plausible_host(s: str) -> Optional[str]:
    s = s.strip().strip("'\"[]").lower()
    if not s or s.startswith(("/", ".", "~", "$")):
        return None
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", s):
        return s
    if s in ("localhost",):
        return s
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", s):
        return None
    if s.rsplit(".", 1)[-1] in _FILE_EXT:
        return None
    return s


def _port_after(toks: list[str], i: int) -> Optional[int]:
    for j in range(i + 1, min(len(toks), i + 8)):
        if toks[j] in ("-p", "-P") and j + 1 < len(toks):
            return _int(toks[j + 1])
    return None


def _int(s: str) -> Optional[int]:
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def _client_of(cmd: str) -> Optional[str]:
    for tok in _tokens(cmd):
        base = os.path.basename(tok)
        if base in _NET_CLIENTS:
            return base
    return None


# ------------------------------------------------------------------- suspicious command shapes
_CMD_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # (regex, tag, short reason)
    (re.compile(r"base64\s+(-d|--decode|-D)\b.*\|\s*(ba|z|da|k)?sh\b|\|\s*base64\s+(-d|--decode)\s*\|\s*(ba|z)?sh", re.S), "cmd:decode_exec", "base64-decoded content piped to a shell"),
    (re.compile(r"(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b", re.S), "cmd:download_exec", "remote script piped straight to a shell"),
    (re.compile(r"(curl|wget)\b[^|]*\|\s*(sudo\s+)?(python3?|perl|ruby|node)\b", re.S), "cmd:download_exec", "remote content piped to an interpreter"),
    (re.compile(r"\b(python3?|perl|ruby|node)\s+-[ce]\s+['\"][^'\"]*(exec|eval|base64|b64decode|compile|__import__|fromCharCode)", re.S), "cmd:inline_exec", "inline interpreter code that decodes or evals"),
    (re.compile(r"\beval\s+[\"$`(]"), "cmd:eval", "shell eval of dynamic content"),
    (re.compile(r"/dev/(tcp|udp)/"), "cmd:reverse_shell", "bash network redirection"),
    (re.compile(r"\b(nc|ncat|netcat)\b.*\s-(e|c)\s", re.S), "cmd:reverse_shell", "netcat with command execution"),
    (re.compile(r"\bsocat\b.*\bexec:", re.I), "cmd:reverse_shell", "socat exec relay"),
    (re.compile(r"\bmkfifo\b.*\b(nc|ncat|sh)\b", re.S), "cmd:reverse_shell", "fifo-based shell relay"),
    (re.compile(r"(\\x[0-9a-f]{2}){6,}", re.I), "cmd:hex_obfuscation", "hex-escaped payload"),
    (re.compile(r"\$\{[A-Za-z_]+:[0-9]+:[0-9]+\}.*\$\{[A-Za-z_]+:[0-9]+:[0-9]+\}"), "cmd:string_slicing", "string-slice obfuscation"),
    (re.compile(r"\bchmod\s+([ug]\+s|[2-7][0-7]{3})\b"), "cmd:setuid", "setuid/setgid bit"),
    (re.compile(r"\b(history\s+-c|unset\s+HISTFILE|HISTSIZE=0|export\s+HISTFILESIZE=0|shred\b.*history|rm\b.*_history)"), "cmd:antiforensics", "shell history tampering"),
    (re.compile(r"\b(crontab\s+-|launchctl\s+(load|bootstrap|submit)|systemctl\s+(--user\s+)?(enable|start)\b|schtasks\s+/create|at\s+now)", re.I), "cmd:persistence", "scheduled task or service persistence"),
    (re.compile(r"\b(nohup|setsid|disown)\b|&\s*$"), "cmd:background", "detached background process"),
    (re.compile(r"\bsudo\b"), "cmd:sudo", "privilege escalation"),
    (re.compile(r"\b(cat|less|more|head|tail|strings|grep|xxd|hexdump|od)\b[^|;&]*(\.ssh/|id_rsa|\.env\b|\.aws/|\.netrc|credentials|auth\.json|\.pem\b|\.key\b|shadow\b)", re.S), "cmd:credential_read", "reads a credential store"),
    (re.compile(r"\b(printenv|env)\s*($|\||>)|\becho\s+\$[A-Z_]*(KEY|TOKEN|SECRET|PASS)", re.S), "cmd:env_dump", "dumps environment variables"),
    (re.compile(r"\bsecurity\s+(find-(generic|internet)-password|dump-keychain|export)\b"), "cmd:keychain", "macOS keychain extraction"),
    (re.compile(r"\b(gh\s+auth\s+token|aws\s+(sts\s+get-session-token|configure\s+get|secretsmanager\s+get-secret-value)|gcloud\s+auth\s+print-access-token|az\s+account\s+get-access-token|vault\s+(read|kv\s+get)|op\s+(read|item\s+get)|pass\s+show|kubectl\s+get\s+secret)", re.I), "cmd:token_fetch", "fetches a live credential from a CLI"),
    (re.compile(r"\b(sqlite3|python3?)\b[^|;]*\b(Login Data|Cookies|cookies\.sqlite|logins\.json)\b", re.I), "cmd:browser_creds", "browser credential store access"),
    (re.compile(r"\bgit\s+push\b"), "cmd:git_push", "pushes to a remote"),
    (re.compile(r"\bgit\s+remote\s+(add|set-url)\b"), "cmd:git_remote_change", "changes a git remote"),
    (re.compile(r"\bgh\s+(repo\s+create|release\s+(create|upload)|gist\s+create|secret\s+set)\b"), "cmd:gh_publish", "publishes through the GitHub CLI"),
    (re.compile(r"\bhermes\s+plugins?\s+(install|enable|disable|remove|update)\b"), "cmd:hermes_plugin", "changes installed plugins"),
    (re.compile(r"\bhermes\s+config\s+set\s+(approvals|terminal\.backend|plugins|hooks|auth|yolo)", re.I), "cmd:hermes_security_config", "changes a Hermes security setting"),
    (re.compile(r"\bhermes\s+(cron|schedule|jobs?)\s+(add|create|enable)\b"), "cmd:hermes_cron", "creates a Hermes scheduled job"),
    (re.compile(r"\b(tar|zip|7z|gzip)\b[^|;]*(\.ssh|\.aws|\.gnupg|\.env|credentials|keychain)", re.I), "cmd:credential_archive", "archives a credential store"),
    (re.compile(r"\b(rm|shred|truncate)\b[^|;]*(/var/log|\.hermes/logs|audit|wtmp|lastlog)", re.I), "cmd:log_tamper", "removes logs"),
    (re.compile(r"\bchmod\s+(-R\s+)?[0-7]*7[0-7]*\s+(/etc|/usr|/bin|~|\$HOME)\b"), "cmd:perm_loosen", "loosens permissions broadly"),
]


def classify_command(cmd: Optional[str]) -> list[tuple[str, str]]:
    """``[(tag, reason), ...]`` for every suspicious shape in *cmd*. Order follows the table."""
    if not cmd:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for rx, tag, reason in _CMD_PATTERNS:
        if tag in seen:
            continue
        if rx.search(cmd):
            out.append((tag, reason))
            seen.add(tag)
    return out


def command_preview(cmd: Optional[str], limit: int = 200) -> str:
    """First line of a command, whitespace-collapsed and bounded (redaction is the caller's job)."""
    if not cmd:
        return ""
    first = str(cmd).strip().splitlines()[0] if str(cmd).strip() else ""
    first = " ".join(first.split())
    return first if len(first) <= limit else first[: limit - 1] + "…"


# ------------------------------------------------------------------------------ tool classes
# Which Hermes tools do what. Names from toolsets.py at upstream 21ae0e1. A tool not listed here is
# recorded as a plain tool.call and classified by its argument names.
FILE_READ_TOOLS = {"read_file", "search_files", "read_terminal", "skill_view"}
FILE_WRITE_TOOLS = {"write_file", "patch"}
EXEC_TOOLS = {"terminal", "execute_code", "process_manage"}
WEB_TOOLS = {"web_search", "web_extract", "x_search"}
BROWSER_TOOLS_PREFIX = ("browser",)
SEND_TOOLS = {"send_message", "react_to_message", "kanban_comment", "kanban_attach", "kanban_attach_url"}
DELEGATE_TOOLS = {"delegate_task"}
CRON_TOOLS = {"cronjob", "cronjob_manage"}
SKILL_TOOLS = {"skill_manage", "skills_list"}
MEMORY_TOOLS = {"memory"}
UNTRUSTED_SOURCE_TOOLS = WEB_TOOLS | {"read_file"}  # read_file only for downloaded/tmp paths

DOWNLOAD_DIRS = re.compile(r"(^|/)(Downloads|Desktop/Downloads|tmp|Temp|var/tmp|Public|Shared|Inbox|attachments?)(/|$)", re.I)


def is_untrusted_path(path: Optional[str]) -> bool:
    return bool(path) and bool(DOWNLOAD_DIRS.search(_norm_path(path)))


def browser_action(tool: str, args: dict) -> Optional[str]:
    """``navigate`` / ``read`` / ``act`` for browser tools, or None."""
    if not tool.startswith(BROWSER_TOOLS_PREFIX):
        return None
    a = str(args.get("action") or args.get("command") or "").lower()
    if "navigate" in a or "goto" in a or "open" in a or args.get("url"):
        return "navigate"
    if any(k in a for k in ("click", "type", "fill", "submit", "press", "upload")):
        return "act"
    return "read"


def first_str(args: dict, *keys: str) -> Optional[str]:
    for k in keys:
        v = args.get(k)
        if isinstance(v, str) and v:
            return v
    return None


__all__ = [
    "classify_path", "paths_in_text", "classify_host", "host_of", "egress_from_command", "classify_command",
    "command_preview", "is_untrusted_path", "browser_action", "first_str", "WEBHOOK_HOSTS", "DEV_HOSTS",
    "FILE_READ_TOOLS", "FILE_WRITE_TOOLS", "EXEC_TOOLS", "WEB_TOOLS", "SEND_TOOLS", "DELEGATE_TOOLS",
    "CRON_TOOLS", "SKILL_TOOLS",
]

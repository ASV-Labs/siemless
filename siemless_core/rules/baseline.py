"""Baseline detections SL-001 … SL-014.

Each rule documents: what it needs (``required_fields``), what it looks for, its ATT&CK mapping
(or why there isn't one), and the false positives an operator should expect. Fixtures for every
rule, positive and negative, live in ``tests/fixtures/rules/``.
"""

from __future__ import annotations

from typing import Optional

from ..events import Event
from . import Finding, RuleContext

from ..attack import technique as _tq


class _T(dict):
    """``T["T1700"]`` → the verified technique record (name, tactic, url) from data/attack.json."""

    def __missing__(self, key):
        v = _tq(key)
        self[key] = v
        return v


T = _T()

MIN = 60 * 1000


def _is_sensitive(e: Event) -> bool:
    return e.kind == "secret.access"


def _is_external_egress(e: Event, ctx: RuleContext) -> bool:
    if e.kind != "net.egress":
        return False
    if "egress:provider" in e.tags:
        return False
    if "egress:private" in e.tags and not ctx.config.get("watch_private_hosts"):
        return False
    if e.action == "send":
        return True  # a message leaves the machine whatever the host
    if ctx.allowlisted_host(e.host):
        return False
    return True


def _label(e: Event) -> str:
    bits = [e.kind]
    if e.tool:
        bits.append(e.tool)
    if e.target:
        bits.append(e.target[:80])
    return " · ".join(bits)


class _Base:
    id = "SL-000"
    name = "base"
    description = ""
    severity = "medium"
    triggers: tuple[str, ...] = ()
    attack: list[dict] = []
    attack_note: Optional[str] = None
    false_positives = ""
    required_fields: tuple[str, ...] = ("kind", "time", "session_id")

    def evaluate(self, event: Event, ctx: RuleContext) -> Optional[Finding]:  # pragma: no cover
        return None

    def _finding(self, event: Event, evidence: list[Event], *, title: str, observed: str, why: str,
                 recommendation: str, missing: list[str], dedupe: str, severity: Optional[str] = None,
                 confidence_cap: Optional[str] = None) -> Finding:
        ev = sorted({e.id: e for e in evidence + [event]}.values(), key=lambda x: x.time)
        return Finding(rule_id=self.id, name=self.name, severity=severity or self.severity, title=title, observed=observed,
                       why=why, evidence=ev, attack=list(self.attack), attack_note=self.attack_note,
                       recommendation=recommendation, missing_evidence=missing, dedupe_key=dedupe,
                       confidence_cap=confidence_cap)


# ----------------------------------------------------------------------------------- SL-001
class SecretAccessThenEgress(_Base):
    id = "SL-001"
    name = "Sensitive access followed by egress"
    description = ("A credential store or key file was targeted, then within the window the same session (or its "
                   "subagent) reached an external destination. The classic exfiltration shape.")
    severity = "high"
    triggers = ("net.egress",)
    attack = [T["T1552.001"], T["T1567"], T["T1700"]]
    attack_note = "T1700 is attached because the actor is an AI agent; T1567.004 replaces T1567 when the host is a known webhook/paste service."
    false_positives = ("Legitimate deploys: reading ~/.aws/credentials then calling AWS; git push after touching .env. "
                       "Allow-list the hosts you deploy to, or the paths your workflow reads.")
    required_fields = ("kind", "time", "session_id", "host", "tags", "target")

    def evaluate(self, event: Event, ctx: RuleContext) -> Optional[Finding]:
        if not _is_external_egress(event, ctx):
            return None
        secrets = ctx.recent(["secret.access"], before=event, include_parents=True,
                             predicate=lambda e: not ctx.allowlisted_path(e.target))
        if not secrets:
            return None
        sev = self.severity
        attack = list(self.attack)
        if "egress:webhook" in event.tags:
            sev = "critical"
            attack = [T["T1552.001"], T["T1567.004"], T["T1700"]]
        elif "egress:dev" in event.tags and event.action != "send":
            sev = "medium"  # package registries and GitHub are usual destinations
        f = self._finding(
            event, secrets[:5],
            title=f"Sensitive access then egress to {event.host or event.target or 'a destination'}",
            observed=(f"{len(secrets)} sensitive-path access(es) ({', '.join(sorted({t for e in secrets for t in e.tags if t.startswith('sensitive:')})[:4])}) "
                      f"preceded a {event.action or 'network'} to {event.host or event.target} via {event.tool}."),
            why="Credential material was in reach of the agent immediately before it contacted the outside world.",
            recommendation=("Check whether the destination is one you expect for this task; rotate the credentials named in the evidence "
                            "if it is not. Add the destination to allow_hosts if this is a routine deploy."),
            missing=["File contents are never recorded, so whether the credential bytes were in the request body is not visible.",
                     "Shell network calls are inferred from command text; the connection itself is not observed."],
            dedupe=f"{event.session_id}:{event.host or event.target}", severity=sev)
        f.attack = attack
        return f


# ----------------------------------------------------------------------------------- SL-002
class InjectionChain(_Base):
    id = "SL-002"
    name = "Untrusted content followed by sensitive action"
    description = ("Content from outside the trust boundary (a web page, search result, browser page or downloaded file) "
                   "entered the context, and within the window the agent targeted a credential store, reached a new "
                   "destination, changed its own configuration or scheduled a job. The indirect prompt-injection shape.")
    severity = "high"
    triggers = ("secret.access", "net.egress", "config.change", "cron.change", "plugin.change")
    attack = [T["T1698"]]
    attack_note = "Attached to the *downstream* action, not to the fetch: reading a web page is not an attack."
    false_positives = ("Research tasks that fetch docs and then edit config on purpose. The finding is medium when the "
                       "downstream action is only a new destination, high when it is credential access or a governance change.")
    required_fields = ("kind", "time", "session_id", "tags")

    def evaluate(self, event: Event, ctx: RuleContext) -> Optional[Finding]:
        if event.kind == "net.egress":
            if not _is_external_egress(event, ctx) or not ctx.first_seen_host(event.host, event.time, event.id):
                return None
        if event.kind == "secret.access" and ctx.allowlisted_path(event.target):
            return None
        taint = ctx.tainted(before=event)
        if not taint:
            return None
        sev = "high" if event.kind in ("secret.access", "config.change", "plugin.change") else "medium"
        src = taint[0]
        return self._finding(
            event, taint[:3],
            title=f"Untrusted {src.action or 'content'} from {src.host or src.tool} preceded {event.kind}",
            observed=(f"{len(taint)} untrusted-content event(s) (latest: {src.tool} {src.action or ''} {src.host or src.target or ''}) "
                      f"then {event.kind} → {event.target or event.host}."),
            why="Instructions hidden in fetched content are the usual way an agent is steered into exactly this sequence.",
            recommendation=("Read the fetched page or file for embedded instructions. If the downstream action was not asked for by the "
                            "user, treat the source as hostile and review what else happened in this turn."),
            missing=["The content itself is not stored, so the injected text is not quoted here; the session transcript has it.",
                     "Causality is temporal: the action followed the fetch inside the window."],
            dedupe=f"{event.session_id}:{event.turn_id}:{event.kind}", severity=sev, confidence_cap="medium")


# ----------------------------------------------------------------------------------- SL-003
class CredentialDiscovery(_Base):
    id = "SL-003"
    name = "Credential discovery"
    description = "A tool call or command targeted a credential store: SSH keys, cloud credentials, .env files, keychains, browser logins, token-fetching CLIs."
    severity = "medium"
    triggers = ("secret.access",)
    attack = [T["T1552"], T["T1555"]]
    attack_note = "Refined per store: T1552.004 for private keys, T1555.001 for the macOS keychain, T1555.003 for browser stores."
    false_positives = "Developers ask agents to fix their .env and ssh config. Severity is low for a single read with no follow-on; SL-001 and SL-002 cover the follow-on."
    required_fields = ("kind", "time", "session_id", "target", "tags")

    def evaluate(self, event: Event, ctx: RuleContext) -> Optional[Finding]:
        if ctx.allowlisted_path(event.target):
            return None
        tags = set(event.tags)
        attack = list(self.attack)
        sev = "low"
        if "sensitive:ssh" in tags or "sensitive:private_key" in tags:
            attack = [T["T1552.004"]]
            sev = "medium"
        if "sensitive:keychain" in tags or "cmd:keychain" in tags:
            attack = [T["T1555.001"]]
            sev = "high"
        if "sensitive:browser" in tags or "cmd:browser_creds" in tags:
            attack = [T["T1555.003"]]
            sev = "high"
        if "sensitive:shell_history" in tags:
            attack = [T["T1552.003"]]
        if "cmd:token_fetch" in tags or "cmd:env_dump" in tags:
            attack = [T["T1552"], T["T1550"]]
            sev = "high"
        if "sensitive:cloud" in tags or "sensitive:hermes_secrets" in tags or "sensitive:dotenv" in tags:
            sev = max(sev, "medium", key=["low", "medium", "high"].index)
        f = self._finding(
            event, [],
            title=f"Credential store targeted: {event.target}",
            observed=f"{event.tool} {event.action or ''} → {event.target} ({', '.join(sorted(t for t in tags if ':' in t))}).",
            why="Credential stores are rarely needed for ordinary tasks; each access is worth a glance, and it is the first step of SL-001.",
            recommendation="If the task did not require this file, review the turn. Consider terminal.credential_files and Hermes's read denylist for stores the agent should never see.",
            missing=["Whether the read returned content is visible only through the tool status; the bytes are not recorded."],
            dedupe=f"{event.session_id}:{event.target}", severity=sev)
        f.attack = attack
        return f


# ----------------------------------------------------------------------------------- SL-004
class NewDestinationAfterSensitive(_Base):
    id = "SL-004"
    name = "First-seen destination near sensitive activity"
    description = "The session reached a host this profile has never contacted before, within the window of a credential access, a config change or an untrusted fetch."
    severity = "medium"
    triggers = ("net.egress",)
    attack = [T["T1071.001"], T["T1567"]]
    attack_note = None
    false_positives = "The first day on a new project is all first-seen hosts. Seed the baseline by running normally for a while; allow-list your SaaS."
    required_fields = ("kind", "time", "session_id", "host")

    def evaluate(self, event: Event, ctx: RuleContext) -> Optional[Finding]:
        if not _is_external_egress(event, ctx) or not event.host or "egress:dev" in event.tags:
            return None
        if not ctx.first_seen_host(event.host, event.time, event.id):
            return None
        context = ctx.recent(["secret.access", "config.change"], before=event, include_parents=True)
        if not context:
            return None
        return self._finding(
            event, context[:3],
            title=f"New destination {event.host} after sensitive activity",
            observed=f"{event.host} had never been contacted by this profile; it was reached via {event.tool} after {context[0].kind} ({context[0].target}).",
            why="Exfiltration and C2 go to places the baseline has not seen.",
            recommendation="Confirm the host belongs to the task. Allow-list it if so.",
            missing=["The baseline is per profile and starts empty; early findings are expected."],
            dedupe=f"{event.session_id}:{event.host}", confidence_cap="medium")


# ----------------------------------------------------------------------------------- SL-005
class Persistence(_Base):
    id = "SL-005"
    name = "Scheduled job or persistence created"
    description = "A Hermes cron job was created or changed, or a shell command installed OS-level persistence (crontab, launchctl, systemd, schtasks)."
    severity = "medium"
    triggers = ("cron.change",)
    attack = [T["T1053"]]
    attack_note = "T1053.003 (Cron) when the mechanism is crontab or a Hermes cron job."
    false_positives = "Users ask for scheduled jobs. The finding is low when the user turn is the direct parent; high when the session was tainted."
    required_fields = ("kind", "time", "session_id", "target", "tags")

    def evaluate(self, event: Event, ctx: RuleContext) -> Optional[Finding]:
        taint = ctx.tainted(before=event)
        sev = "high" if taint else "low"
        attack = [T["T1053.003"]] if ("persistence:cron" in event.tags) else list(self.attack)
        f = self._finding(
            event, taint[:2],
            title=f"Persistence: {event.action} {event.target or 'scheduled job'}",
            observed=f"{event.tool or 'command'} {event.action} → {event.target}" + (" after untrusted content entered the context." if taint else "."),
            why="A job that runs later runs without the user watching; created after untrusted input it is a textbook foothold.",
            recommendation="Open the job and read its prompt/command. Hermes pauses nothing by itself; delete what you did not ask for.",
            missing=["Whether the job's content is malicious is not assessed here; only that it was created."],
            dedupe=f"{event.session_id}:{event.target}", severity=sev)
        f.attack = attack
        return f


# ----------------------------------------------------------------------------------- SL-006
class PluginDrift(_Base):
    id = "SL-006"
    name = "Plugin or skill set changed"
    description = "A plugin was installed, enabled, disabled or removed, or a skill was created/installed — the agent changing its own capabilities."
    severity = "medium"
    triggers = ("plugin.change", "skill.change")
    attack = []
    attack_note = "No exact ATT&CK technique: extending an agent's own toolset is closest to T1195 (Supply Chain Compromise) only when the source is untrusted, which this rule cannot see."
    false_positives = "Deliberate `hermes plugins install`. Low unless the session was tainted or the change came from a subagent."
    required_fields = ("kind", "time", "session_id", "target")

    def evaluate(self, event: Event, ctx: RuleContext) -> Optional[Finding]:
        if event.kind == "skill.change" and event.action in ("list", "view", "read"):
            return None
        taint = ctx.tainted(before=event)
        from_child = bool(ctx.parent())
        sev = "high" if (taint or from_child) else "low"
        return self._finding(
            event, taint[:2],
            title=f"Capability change: {event.kind} {event.action} {event.target or ''}".strip(),
            observed=f"{event.tool or 'command'} {event.action} → {event.target}" + (" in a subagent session" if from_child else "") + (" after untrusted content." if taint else "."),
            why="New plugins and skills run with the agent's full authority on the next turn.",
            recommendation="Verify the plugin's source and pin. `hermes plugins list` shows what is enabled.",
            missing=["The installed code is not inspected by SIEMless."],
            dedupe=f"{event.session_id}:{event.kind}:{event.target}", severity=sev)


# ----------------------------------------------------------------------------------- SL-007
class ApprovalAnomaly(_Base):
    id = "SL-007"
    name = "Approval anomaly"
    description = "Repeated denials, an approval burst, or a tool call that retried the same approval pattern right after a denial."
    severity = "medium"
    triggers = ("approval.response", "approval.request", "tool.call")
    attack = []
    attack_note = "Behavioural, not a technique: a denied agent that keeps trying is the signal."
    false_positives = "A user denying several unrelated prompts in a row. Threshold is configurable (approval_denies, approval_burst)."
    required_fields = ("kind", "time", "session_id", "outcome", "attrs")

    def evaluate(self, event: Event, ctx: RuleContext) -> Optional[Finding]:
        denies_n = int(ctx.config.get("approval_denies", 3))
        burst_n = int(ctx.config.get("approval_burst", 6))
        if event.kind == "approval.response" and event.outcome == "denied":
            n = ctx.denies_within(event, 5 * MIN)
            if n >= denies_n:
                recent = ctx.recent(["approval.response"], before=event, within_ms=5 * MIN, predicate=lambda e: e.outcome == "denied")
                return self._finding(event, recent[:denies_n], title=f"{n} approvals denied in 5 minutes",
                                     observed=f"The user denied {n} approval prompts within five minutes (latest: {event.target}).",
                                     why="An agent repeatedly asking for things the user refuses is either confused or steered.",
                                     recommendation="Stop the session and read what it is trying to do.",
                                     missing=[], dedupe=f"{event.session_id}:denies")
        if event.kind == "approval.request":
            reqs = ctx.recent(["approval.request"], before=event, within_ms=MIN)
            if len(reqs) + 1 >= burst_n:
                return self._finding(event, reqs[:burst_n], title=f"{len(reqs) + 1} approval prompts in one minute",
                                     observed=f"{len(reqs) + 1} dangerous-command prompts were raised within sixty seconds.",
                                     why="Prompt fatigue: a burst pushes the user to approve without reading.",
                                     recommendation="Pause and review the pending commands before approving more.",
                                     missing=[], dedupe=f"{event.session_id}:burst", severity="low")
        if event.kind == "tool.call" and event.tool in ("terminal", "execute_code"):
            denied = ctx.recent(["approval.response"], before=event, within_ms=2 * MIN, predicate=lambda e: e.outcome == "denied")
            if not denied:
                return None
            sha = (event.attrs.get("args") or {}).get("command")
            for d in denied:
                if d.target and event.attrs.get("args") and isinstance(sha, str) and d.target[:40] and d.target[:40] in str(sha):
                    return self._finding(event, [d], title="Command retried after denial",
                                         observed=f"A terminal call resembling the denied command ({d.target[:60]}) ran within two minutes of the denial.",
                                         why="Working around a denial is exactly what approvals exist to prevent.",
                                         recommendation="Check whether the retried form avoided the approval pattern; report it as a Hermes guard gap if so.",
                                         missing=["Resemblance is a prefix match on the redacted command preview."],
                                         dedupe=f"{event.session_id}:retry:{d.id}", severity="high")
        return None


# ----------------------------------------------------------------------------------- SL-008
class SubagentScope(_Base):
    id = "SL-008"
    name = "Subagent acted outside its parent's scope"
    description = "A delegated child session accessed credentials, reached an external host or changed configuration when its parent had done none of those in the window."
    severity = "high"
    triggers = ("secret.access", "net.egress", "config.change", "cron.change", "plugin.change")
    attack = []
    attack_note = "Delegation itself is not a technique; the finding carries the child's action's mapping via SL-001/003."
    false_positives = "A parent that delegates 'deploy this' to a child that then legitimately reads credentials. Allow-list paths/hosts for that workflow."
    required_fields = ("kind", "time", "session_id", "parent_session_id")

    def evaluate(self, event: Event, ctx: RuleContext) -> Optional[Finding]:
        parent = ctx.parent()
        if parent is None:
            return None
        if event.kind == "net.egress" and not _is_external_egress(event, ctx):
            return None
        if event.kind == "secret.access" and ctx.allowlisted_path(event.target):
            return None
        lo = event.time - ctx.window_ms
        parent_same = [e for e in parent.events if e.kind == event.kind and lo <= e.time <= event.time]
        if parent_same:
            return None
        start = [e for e in parent.events if e.kind == "subagent.start" and e.child_session_id == ctx.state.session_id]
        return self._finding(
            event, start[-1:],
            title=f"Subagent {event.kind} outside parent scope: {event.target or event.host}",
            observed=f"Child session {ctx.state.session_id[:12]}… did {event.kind} ({event.target or event.host}); its parent did nothing of the kind in the window.",
            why="A child agent's goal is a brief from the parent; a sensitive action the parent never took is privilege propagation.",
            recommendation="Read the child's goal (subagent.start) and its tool history (subagent.stop) in the evidence.",
            missing=["Child tool history is metadata-only by Hermes design: tool names and bounded targets, no arguments."],
            dedupe=f"{ctx.state.session_id}:{event.kind}")


# ----------------------------------------------------------------------------------- SL-009
class SuspiciousCommand(_Base):
    id = "SL-009"
    name = "Suspicious command shape"
    description = "Encoded or downloaded content piped to an interpreter, reverse-shell constructs, hex obfuscation, setuid bits, log or history tampering."
    severity = "high"
    triggers = ("process.exec",)
    attack = [T["T1059.004"], T["T1027"]]
    attack_note = "T1105 for download-and-execute; T1140 for decode-and-run; T1070.003 and T1690 for history tampering; shell rc edits are SL-010."
    false_positives = "Installer one-liners (`curl … | sh`) are common and dangerous in equal measure; the finding says which shape fired."
    required_fields = ("kind", "time", "session_id", "tags", "target")

    _SEV = {"cmd:reverse_shell": "critical", "cmd:decode_exec": "high", "cmd:download_exec": "high", "cmd:inline_exec": "high",
            "cmd:hex_obfuscation": "high", "cmd:string_slicing": "medium", "cmd:antiforensics": "high", "cmd:log_tamper": "high",
            "cmd:setuid": "high", "cmd:eval": "medium", "cmd:credential_archive": "high", "cmd:perm_loosen": "medium"}

    def evaluate(self, event: Event, ctx: RuleContext) -> Optional[Finding]:
        hits = [t for t in event.tags if t in self._SEV]
        if not hits:
            return None
        order = ["low", "medium", "high", "critical"]
        sev = max((self._SEV[t] for t in hits), key=order.index)
        attack = list(self.attack)
        if "cmd:download_exec" in hits:
            attack.append(T["T1105"])
        if "cmd:decode_exec" in hits or "cmd:hex_obfuscation" in hits:
            attack.append(T["T1140"])
        if "cmd:antiforensics" in hits:
            attack += [T["T1070.003"], T["T1690"]]
        if "cmd:log_tamper" in hits:
            attack.append(T["T1070"])
        reasons = event.attrs.get("reasons") or []
        f = self._finding(
            event, [],
            title=f"Suspicious command: {', '.join(h.split(':', 1)[1] for h in hits)}",
            observed=f"{event.tool} ran `{event.target}` — {'; '.join(reasons[:3])}.",
            why="These shapes are how payloads hide from review: the command the user sees is not the code that runs.",
            recommendation="Decode or fetch the payload yourself before letting a similar command run again; consider a pre_tool_call guard plugin for these shapes.",
            missing=["Only the command text is visible; what the decoded or downloaded content did is not."],
            dedupe=f"{event.session_id}:{event.attrs.get('command_sha')}", severity=sev)
        f.attack = attack
        return f


# ----------------------------------------------------------------------------------- SL-010
class SecurityConfigTamper(_Base):
    id = "SL-010"
    name = "Security configuration or instruction file changed"
    description = "Hermes config/.env/hooks/plugins, approval mode, agent instruction files (SOUL.md, AGENTS.md, CLAUDE.md), shell rc files, SSH authorized_keys or OS persistence dirs were written."
    severity = "high"
    triggers = ("config.change",)
    attack = [T["T1685"]]
    attack_note = "T1685 (Defense Impairment; T1562.001 is revoked in ATT&CK 20) for Hermes config and hooks; T1685.007 when approvals are weakened; T1546.004 for shell rc files; T1098.004 for authorized_keys."
    false_positives = "The user editing their own config through the agent. Approval-mode changes are always reported."
    required_fields = ("kind", "time", "session_id", "target", "tags")

    def evaluate(self, event: Event, ctx: RuleContext) -> Optional[Finding]:
        if ctx.allowlisted_path(event.target):
            return None
        tags = set(event.tags)
        attack = list(self.attack)
        sev = "medium"
        if "config:shell_rc" in tags:
            attack = [T["T1546.004"]]
        if "config:ssh_config" in tags:
            attack = [T["T1098.004"]]
        if "config:approvals" in tags:
            attack = [T["T1685.007"]]  # the agent weakening its own guardrails
            sev = "high"
        elif "config:hermes_config" in tags or "config:hermes_env" in tags or "config:hermes_hooks" in tags:
            sev = "high"
        if "config:agent_instructions" in tags:
            sev = "high"
        taint = ctx.tainted(before=event)
        if taint:
            sev = "critical" if sev == "high" else "high"
        f = self._finding(
            event, taint[:2],
            title=f"Governance change: {event.target}",
            observed=f"{event.tool or 'command'} {event.action} → {event.target} ({', '.join(sorted(t for t in tags if t.startswith('config:')))})" + (" after untrusted content." if taint else "."),
            why="These files decide what the agent is allowed to do and what it believes it is; changing them is how a compromise persists.",
            recommendation="Diff the file. If approvals were weakened, restore them before the next turn runs.",
            missing=["The diff is not captured; only the path and the actor."],
            dedupe=f"{event.session_id}:{event.target}", severity=sev)
        f.attack = attack
        return f


# ----------------------------------------------------------------------------------- SL-011
class RepositoryPublish(_Base):
    id = "SL-011"
    name = "Code published after sensitive access"
    description = "git push, a remote change, or a GitHub CLI publish happened in a session that had touched a credential store or a .env file."
    severity = "medium"
    triggers = ("net.egress",)
    attack = [T["T1567.001"]]
    attack_note = "T1567.001 Exfiltration to Code Repository; secret-in-repo leaks are the common case."
    false_positives = "Normal development after editing .env.example. Allow-list .env.example / templates."
    required_fields = ("kind", "time", "session_id", "tags")

    def evaluate(self, event: Event, ctx: RuleContext) -> Optional[Finding]:
        if "egress:publish" not in event.tags:
            return None
        secrets = ctx.recent(["secret.access"], before=event, within_ms=30 * MIN, include_parents=True,
                             predicate=lambda e: not ctx.allowlisted_path(e.target))
        if not secrets:
            return None
        sev = "high" if "cmd:git_remote_change" in event.tags else "medium"
        return self._finding(
            event, secrets[:3],
            title="Publish after credential access",
            observed=f"`{event.target}` ran after {secrets[0].target} was accessed.",
            why="Credentials that were just read are one `git add .` away from a public repository.",
            recommendation="Run a secret scan on the pushed range; rotate if anything matched.",
            missing=["Whether the pushed commits contain the secret is not checked here."],
            dedupe=f"{event.session_id}:publish", severity=sev)


# ----------------------------------------------------------------------------------- SL-012
class WebhookTransfer(_Base):
    id = "SL-012"
    name = "Data sent to a webhook or paste service"
    description = "A request to a webhook, tunnel, paste or OOB-interaction service (Discord/Slack webhooks, webhook.site, ngrok, pastebin, interact.sh …)."
    severity = "medium"
    triggers = ("net.egress",)
    attack = [T["T1567.004"]]
    attack_note = None
    false_positives = "Teams that notify Slack from scripts. Allow-list your own webhook host; the finding is high only when sensitive access preceded it (then SL-001 fires too)."
    required_fields = ("kind", "time", "session_id", "host", "tags")

    def evaluate(self, event: Event, ctx: RuleContext) -> Optional[Finding]:
        if "egress:webhook" not in event.tags or ctx.allowlisted_host(event.host):
            return None
        taint = ctx.tainted(before=event)
        sev = "high" if taint else "medium"
        paste = any(p in (event.host or "") for p in ("pastebin", "paste.", "hastebin", "ghostbin", "dpaste", "termbin", "ix.io", "0x0.st", "transfer.sh", "file.io"))
        f = self._finding(
            event, taint[:1],
            title=f"Webhook/paste destination: {event.host}",
            observed=f"{event.tool} {event.action} → {event.target}" + (" after untrusted content." if taint else "."),
            why="These services accept anonymous POSTs and are the standard drop point for exfiltration.",
            recommendation="If you did not set this webhook up, treat it as hostile and look at what was in the request (SL-001 evidence).",
            missing=["Request bodies are not recorded."],
            dedupe=f"{event.session_id}:{event.host}", severity=sev)
        if paste:
            f.attack = [T["T1567.003"]]
        return f


# ----------------------------------------------------------------------------------- SL-013
class AgentToAgentTransfer(_Base):
    id = "SL-013"
    name = "Message or delegation after sensitive access"
    description = "A send_message / kanban comment, or a subagent spawn, followed a credential access: data moving between agents or out through a chat channel."
    severity = "medium"
    triggers = ("net.egress", "subagent.start")
    attack = [T["T1041"]]
    attack_note = "A chat platform the agent already talks on is its existing channel; T1041 (Exfiltration Over C2 Channel) is the nearest fit and is marked approximate."
    false_positives = "Status updates to the owner after a deploy. Low unless the message is large or goes to a channel the session had not used."
    required_fields = ("kind", "time", "session_id", "action")

    def evaluate(self, event: Event, ctx: RuleContext) -> Optional[Finding]:
        if event.kind == "net.egress" and event.action != "send":
            return None
        secrets = ctx.recent(["secret.access"], before=event, include_parents=True,
                             predicate=lambda e: not ctx.allowlisted_path(e.target))
        if not secrets:
            return None
        size = int(event.attrs.get("message_chars") or 0)
        sev = "high" if size > 2000 else "medium"
        what = "message" if event.kind == "net.egress" else "delegation"
        return self._finding(
            event, secrets[:3],
            title=f"{what.capitalize()} after credential access",
            observed=f"{event.tool or 'subagent'} {event.action} ({size} chars) after {secrets[0].target} was accessed.",
            why="A credential read followed by a message is how secrets leave through the agent's own chat channel.",
            recommendation="Open the message in the transcript; rotate anything that appears in it.",
            missing=["Message text is hashed, not stored."],
            dedupe=f"{event.session_id}:{what}", severity=sev, confidence_cap="medium")


# ----------------------------------------------------------------------------------- SL-014
class HermesHomeAccess(_Base):
    id = "SL-014"
    name = "Access to Hermes's own secrets or another profile"
    description = "The agent read or wrote under HERMES_HOME's secret files (.env, auth.json) or another profile's directory."
    severity = "high"
    triggers = ("secret.access", "file.read", "file.write")
    attack = [T["T1552.001"]]
    attack_note = None
    false_positives = "The owner debugging their own install. Always worth a look."
    required_fields = ("kind", "time", "session_id", "target", "tags")

    def evaluate(self, event: Event, ctx: RuleContext) -> Optional[Finding]:
        tgt = event.target or ""
        hermes_secret = "sensitive:hermes_secrets" in event.tags
        other_profile = "/.hermes/profiles/" in tgt and event.kind in ("file.read", "file.write")
        if not (hermes_secret or other_profile):
            return None
        return self._finding(
            event, [],
            title=f"Hermes home access: {tgt}",
            observed=f"{event.tool} {event.action} → {tgt}.",
            why="Hermes's own credential files and other profiles' homes are the keys to every connected service.",
            recommendation="Confirm this was you. Hermes's read denylist can block these paths for the agent entirely.",
            missing=[],
            dedupe=f"{event.session_id}:{tgt}")


RULES = [
    SecretAccessThenEgress(), InjectionChain(), CredentialDiscovery(), NewDestinationAfterSensitive(), Persistence(),
    PluginDrift(), ApprovalAnomaly(), SubagentScope(), SuspiciousCommand(), SecurityConfigTamper(), RepositoryPublish(),
    WebhookTransfer(), AgentToAgentTransfer(), HermesHomeAccess(),
]

__all__ = ["RULES", "T"]

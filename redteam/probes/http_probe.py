"""
Generic HTTP service probe.

Two-step LLM workflow:
  Step 1 — Identify app + auth status from page content
  Step 2 — If no auth: write escalation note and alert human
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path

import httpx
import yaml
from markitdown import MarkItDown

from ..config import config
from ..llm import LLMClient, Message, TextBlock
from ..notify import send_red_team_escalation

log = logging.getLogger(__name__)

_mdit = MarkItDown()

# ---------------------------------------------------------------------------
# Escalation rules — loaded from escalation_rules.yaml
# ---------------------------------------------------------------------------

def _load_rules() -> str:
    """Load escalation_rules.yaml and format as plain text for the LLM prompt."""
    rules_path = Path(__file__).parents[2] / "escalation_rules.yaml"
    if not rules_path.exists():
        return ""
    try:
        rules = yaml.safe_load(rules_path.read_text())
        lines = ["ESCALATION RULES (apply these when making your decision):"]
        for item in rules.get("always_escalate", []):
            lines.append(f"- ALWAYS ESCALATE if service matches: {item['name']}")
            lines.append(f"  Reason: {item['reason'].strip()}")
        lines.append("- ESCALATE if no authentication detected on any other service")
        return "\n".join(lines)
    except Exception as e:
        log.warning("Could not load escalation_rules.yaml: %s", e)
        return ""

_ESCALATION_RULES = _load_rules()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ServiceIdentification:
    application: str
    version: str | None
    has_auth: bool
    auth_type: str
    confidence: str
    evidence: str


@dataclass
class HttpProbeResult:
    ip: str
    port: int
    url: str
    http_status: str
    headers: str
    markdown: str
    hints: str = ""
    verified_url: str = ""          # most specific URL that returned real content
    identification: ServiceIdentification | None = None
    escalation_note: str | None = None
    needs_escalation: bool = False


# ---------------------------------------------------------------------------
# Kali fetch
# ---------------------------------------------------------------------------

async def _kali_exec(client: httpx.AsyncClient, command: str) -> str:
    resp = await client.post(
        f"{config.kali_api_url}/execute",
        headers={"Authorization": f"Bearer {config.kali_api_token}"},
        json={"command": command},
        timeout=20,
    )
    resp.raise_for_status()
    return resp.json().get("output", "").strip()


# Well-known secondary paths that reveal app identity even on SPAs.
# Tried in order — first path returning non-404 content wins.
_FINGERPRINT_PATHS = [
    # Auth detection — login pages
    "/remote/login",                # FortiGate SSL-VPN login page
    "/login",                       # FortiGate, FortiManager, many web apps
    "/login.html",                  # FortiGate alternative
    "/ng/",                         # FortiGate next-gen UI
    "/cgi-bin/login",               # FortiGate CGI
    # Monitoring stack
    "/api/v1/status/runtimeinfo",   # Prometheus
    "/api/v1/targets",              # Prometheus
    "/metrics",                     # Prometheus node exporter
    # Dashboards
    "/api/status",                  # Kibana / OpenSearch Dashboards
    "/api/health",                  # Grafana, generic
    "/api/frontend/settings",       # Grafana
    # Generic
    "/healthz",                     # Kubernetes ingress, generic
    "/version",                     # version endpoint
    "/api/",                        # generic REST API discovery
    "/admin",                       # generic admin panel
]


async def _fetch_page(client: httpx.AsyncClient, ip: str, port: int) -> tuple[str, str, str, str, str]:
    """Returns (status_line, headers, html_body, fingerprint_hints, verified_path) via Kali proxy.

    verified_path is the most specific path that returned real content
    (a fingerprint path if one hit, otherwise "/").
    """
    scheme = "https" if port in (443, 8443, 9443, 1443) else "http"
    url = f"{scheme}://{ip}:{port}/"

    headers_raw = await _kali_exec(client, f"curl -skL --max-time 10 -I '{url}'")
    body_raw    = await _kali_exec(client, f"curl -skL --max-time 10 -A 'Mozilla/5.0' '{url}'")

    # For HTTPS — extract cert subject/issuer (reveals product identity)
    hints = ""
    if scheme == "https":
        cert = await _kali_exec(
            client,
            f"echo | openssl s_client -connect {ip}:{port} 2>/dev/null "
            f"| openssl x509 -noout -subject -issuer -dates 2>/dev/null"
        )
        if cert.strip():
            hints += f"\n--- SSL certificate ---\n{cert.strip()}\n"

    # Try fingerprint paths — first hit wins; record the path for the verified URL
    verified_path = "/"
    for path in _FINGERPRINT_PATHS:
        probe = await _kali_exec(
            client,
            f"curl -sk --max-time 5 '{scheme}://{ip}:{port}{path}' | head -c 500"
        )
        if probe and "404" not in probe[:50] and len(probe) > 10:
            hints += f"\n--- {path} ---\n{probe[:500]}\n"
            verified_path = path
            break  # one good hint is enough

    # Always run gobuster — LLM needs full picture regardless of auth status
    gobuster = await _kali_exec(
        client,
        f"gobuster dir -u {url} "
        f"-w /usr/share/wordlists/dirb/common.txt "
        f"-t 10 -q -k --timeout 5s "
        f"-b 401,403,404 2>/dev/null | head -30"
    )
    if gobuster.strip():
        hints += f"\n--- gobuster paths ---\n{gobuster.strip()}\n"

    status = next((l for l in headers_raw.splitlines() if l.startswith("HTTP/")), "unknown")
    return status, headers_raw, body_raw, hints, verified_path


def _to_markdown(html: str) -> str:
    """Convert HTML to markdown. Falls back to title+text extraction for SPAs."""
    import re

    # Try markitdown first
    try:
        result = _mdit.convert_stream(
            BytesIO(html.encode("utf-8", errors="replace")),
            file_extension=".html",
        )
        if result.text_content.strip():
            return result.text_content[:6000]
    except Exception as e:
        log.warning("markitdown conversion failed: %s", e)

    # SPA fallback — extract title + strip tags
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    title = title_match.group(1).strip() if title_match else ""
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text).strip()
    return f"Page title: {title}\n\n{text[:5000]}"


# ---------------------------------------------------------------------------
# LLM Step 1 — identify app + auth
# ---------------------------------------------------------------------------

_IDENTIFY_PROMPT = """You are a security analyst. A web page was fetched from {url}.

HTTP response headers:
{headers}

Page content (markdown):
{markdown}

API fingerprint hints (secondary probes):
{hints}

If the response contains Prometheus-format metrics (lines starting with # HELP or # TYPE),
do NOT assume it is Prometheus just because of the format — many applications expose metrics
in this format. Read the actual metric names in the crawled content to identify the specific
application. The metric names uniquely identify the exporter (e.g. a database exporter has
database metric names, a container runtime has container metric names, etc.).

For has_auth determination:
- has_auth=false means actual application content is accessible without credentials
- If the root returns 404 AND gobuster found NO accessible paths, set has_auth=true —
  there is no accessible content to expose, so this is NOT an unauthenticated exposure
- Only set has_auth=false if real content (200 responses, data, APIs, dashboards) is reachable

Respond ONLY with a JSON object — no explanation, no markdown fences:
{{
  "application": "<specific application name — e.g. CRI-O metrics exporter, Prometheus Node Exporter, Prometheus, kubelet, unknown>",
  "version": "<version string if visible, else null>",
  "has_auth": <true if a login form, HTTP 401/403, or redirect to login page is present — false if app content is directly accessible>,
  "auth_type": "<login form / basic auth / SSO / redirect / none>",
  "confidence": "<high / medium / low>",
  "evidence": "<one sentence: what specific element told you the application name and auth status>"
}}"""


async def _identify(url: str, headers: str, markdown: str, hints: str, llm: LLMClient) -> ServiceIdentification | None:
    prompt = _IDENTIFY_PROMPT.format(
        url=url, headers=headers[:500], markdown=markdown, hints=hints[:1000] or "(none)"
    )
    messages = [Message(role="user", content=[TextBlock(text=prompt)])]
    response = await llm.call(messages=messages, system_prompt=None, tools=[])
    text = "".join(b.text for b in response.content if isinstance(b, TextBlock)).strip()

    # Extract JSON — LLM sometimes wraps in ```
    import re
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        log.warning("LLM identification returned no JSON: %s", text[:200])
        return None
    try:
        d = json.loads(match.group())
        return ServiceIdentification(
            application=d.get("application", "unknown"),
            version=d.get("version"),
            has_auth=bool(d.get("has_auth", True)),
            auth_type=d.get("auth_type", "unknown"),
            confidence=d.get("confidence", "low"),
            evidence=d.get("evidence", ""),
        )
    except json.JSONDecodeError as e:
        log.warning("Failed to parse identification JSON: %s", e)
        return None


# ---------------------------------------------------------------------------
# LLM Step 2 — escalation note (only when no auth)
# ---------------------------------------------------------------------------

_ESCALATE_PROMPT = """You are a security analyst reviewing a web service found on a public IP.

Target: {url}
Application identified: {application} {version}
Initial auth assessment: {evidence}

All collected evidence (page content, API responses, gobuster paths):
{page_context}

{rules}

Based on ALL evidence and the rules above, make a final escalation decision.

Do NOT escalate if:
- Your confidence is low — insufficient evidence to make a reliable determination
- Authentication is confirmed: login form, redirect to /login, HTTP 401/403, or session cookies
- The root returns 301/302 redirect — it just points elsewhere, no content is exposed here
- The root returns 404 AND gobuster found no accessible paths — empty server, not a finding

Only escalate if unauthenticated access to real content is confirmed with medium or high
confidence, OR if the always_escalate rules above explicitly match.

Respond ONLY with a JSON object — no explanation, no markdown fences:
{{
  "escalate": <true or false>,
  "reason": "<one sentence explaining your decision>",
  "note": "<if escalate=true: 4-6 sentence escalation note starting with the direct URL, citing specific evidence found, what an attacker can do, and recommended action. If escalate=false: null>"
}}"""


async def _escalate(result: HttpProbeResult, llm: LLMClient) -> tuple[bool, str]:
    """Returns (should_escalate, note_or_reason)."""
    ident = result.identification
    version_str = f"v{ident.version}" if ident and ident.version else ""
    page_context = f"{result.markdown}\n\nAPI hints + gobuster:\n{result.hints}\n\nHeaders:\n{result.headers[:300]}".strip()[:2500]
    prompt = _ESCALATE_PROMPT.format(
        url=result.url,
        application=ident.application if ident else "unknown",
        version=version_str,
        evidence=ident.evidence if ident else "unknown",
        page_context=page_context,
        rules=_ESCALATION_RULES,
    )
    messages = [Message(role="user", content=[TextBlock(text=prompt)])]
    response = await llm.call(messages=messages, system_prompt=None, tools=[])
    text = "".join(b.text for b in response.content if isinstance(b, TextBlock)).strip()

    import re
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        log.warning("Escalation LLM returned no JSON: %s", text[:200])
        return False, ""
    try:
        d = json.loads(match.group())
        return bool(d.get("escalate", False)), d.get("note") or d.get("reason", "")
    except json.JSONDecodeError:
        return False, ""


# ---------------------------------------------------------------------------
# Main probe entry point
# ---------------------------------------------------------------------------

async def probe_http(ip: str, port: int, alert: bool = True) -> HttpProbeResult:
    """Probe a single HTTP/S port — identify app, check auth, escalate if open.

    Set alert=False to suppress immediate email — use consolidate_and_alert()
    after collecting all results for the same IP.
    """
    scheme = "https" if port in (443, 8443, 9443, 1443) else "http"
    url = f"{scheme}://{ip}:{port}/"

    llm = LLMClient(
        base_url=config.vllm_base_url,
        model=config.vllm_model,
        api_key=config.vllm_api_key,
        temperature=0.1,
        verify_ssl=config.vllm_verify_ssl,
    )

    async with httpx.AsyncClient(verify=False) as client:
        log.info("Fetching %s via Kali proxy", url)
        status, headers, html, hints, verified_path = await _fetch_page(client, ip, port)

    markdown = _to_markdown(html)

    scheme = "https" if port in (443, 8443, 9443, 1443) else "http"
    verified_url = f"{scheme}://{ip}:{port}{verified_path}"

    result = HttpProbeResult(
        ip=ip, port=port, url=url,
        http_status=status,
        headers=headers,
        markdown=markdown,
        hints=hints,
        verified_url=verified_url,
    )

    # Step 1 — identify
    log.info("Identifying application at %s", url)
    result.identification = await _identify(url, headers, markdown, hints, llm)

    if result.identification:
        ident = result.identification
        log.info(
            "%s → app=%s auth=%s confidence=%s",
            url, ident.application, ident.has_auth, ident.confidence
        )

        # Step 2 — LLM makes final escalation decision based on all evidence
        log.info("Asking pony for final escalation decision on %s", url)
        should_escalate, note = await _escalate(result, llm)
        if should_escalate:
            result.escalation_note = note
            result.needs_escalation = True
            log.warning("ESCALATE: %s — %s", url, ident.application)
            if alert:
                _alert_human(result)
        else:
            log.info("No escalation: %s — %s", url, note)

    return result


def _alert_human(result: HttpProbeResult) -> None:
    """Log escalation to stdout and send email notification."""
    ident = result.identification
    app   = ident.application if ident else "unknown"
    ver   = f" v{ident.version}" if ident and ident.version else ""

    # Always log to stdout
    print("\n" + "!" * 60)
    print(f"ESCALATION — UNAUTHENTICATED SERVICE EXPOSED")
    print(f"  Target      : {result.url}")
    print(f"  Application : {app}{ver}")
    print(f"  Auth        : {ident.auth_type if ident else 'none'}")
    print(f"  Evidence    : {ident.evidence if ident else ''}")
    print(f"\n{result.escalation_note}")
    print("!" * 60 + "\n")

    # Send email — fail-open (SMTP unconfigured = log only)
    auth_status = (
        ident.auth_type
        if ident and ident.has_auth and ident.auth_type not in ("none", "")
        else "none"
    )
    sent = send_red_team_escalation(
        ip=result.ip,
        port=result.port,
        application=f"{app}{ver}",
        escalation_note=result.escalation_note or "",
        evidence=ident.evidence if ident else "",
        auth_status=auth_status,
        target_url=result.verified_url,
    )
    if not sent:
        log.warning("Email not sent — configure EMAIL_SERVER/USERNAME/PASSWORD in .env to enable")


def consolidate_and_alert(ip: str, results: list[HttpProbeResult]) -> None:
    """Send one consolidated escalation email for all findings on the same IP."""
    findings = [r for r in results if r.needs_escalation]
    if not findings:
        return

    # Build combined escalation note
    lines = [f"Red team assessment found {len(findings)} finding(s) on {ip}:\n"]
    for r in findings:
        ident = r.identification
        app = ident.application if ident else "unknown"
        ver = f" v{ident.version}" if ident and ident.version else ""
        auth_str = f"auth={ident.auth_type}" if ident else "no auth"
        lines.append(f"Port {r.port} — {app}{ver} ({auth_str})")
        if r.escalation_note:
            lines.append(r.escalation_note)
        lines.append("")

    combined_note = "\n".join(lines)

    # Use first finding's app as subject identifier
    first = findings[0]
    ident = first.identification
    apps = ", ".join(dict.fromkeys(
        r.identification.application for r in findings if r.identification
    ))

    # Print consolidated summary
    print("\n" + "!" * 60)
    print(f"CONSOLIDATED ESCALATION — {ip} ({len(findings)} findings)")
    for r in findings:
        app = r.identification.application if r.identification else "unknown"
        print(f"  Port {r.port:5d} — {app}")
    print(f"\n{combined_note}")
    print("!" * 60 + "\n")

    # auth_status: "none" if all no-auth; otherwise the auth_type of the first finding with auth
    auth_status = "none"
    for r in findings:
        if r.identification and r.identification.has_auth and r.identification.auth_type not in ("none", ""):
            auth_status = r.identification.auth_type
            break

    # Evidence: per-port summary from actual identification results
    evidence_parts = [
        f"port {r.port}: {r.identification.evidence}"
        for r in findings if r.identification and r.identification.evidence
    ]
    evidence = "; ".join(evidence_parts) or f"{len(findings)} port(s) flagged"

    sent = send_red_team_escalation(
        ip=ip,
        port=findings[0].port,
        application=apps,
        escalation_note=combined_note,
        evidence=evidence,
        auth_status=auth_status,
        target_url=findings[0].verified_url,
    )
    if not sent:
        log.warning("Consolidated email not sent for %s — configure SMTP in .env", ip)

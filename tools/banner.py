#!/usr/bin/env python3
"""Draw docs/banner.png (1200x600, 2:1 as the catalog wants) and docs/social-preview.png (1280x640).

Design: ASV Labs blue-black (#0F1419) field, cyan (#62C6D3) accent, a left-to-right event flow —
hook glyphs → a correlation knot → a finding card — drawn with plain PIL. No external assets.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
BG = (15, 20, 25)
INK = (232, 238, 242)
MUTED = (128, 142, 155)
CYAN = (98, 198, 211)
RED = (235, 87, 87)
AMBER = (242, 174, 73)
PANEL = (22, 29, 36)
LINE = (38, 48, 58)

FONTS = {
    "bold": "/usr/share/fonts/opentype/inter/Inter-Bold.otf",
    "semi": "/usr/share/fonts/opentype/inter/Inter-SemiBold.otf",
    "reg": "/usr/share/fonts/opentype/inter/Inter-Regular.otf",
    "mono": "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
}


def font(kind: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(FONTS[kind], size)


def banner(w: int, h: int, out: Path, tagline: bool = True) -> None:
    s = 4  # supersample
    W, H = w * s, h * s
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)

    # faint grid
    for x in range(0, W, 48 * s):
        d.line([(x, 0), (x, H)], fill=(19, 25, 31), width=s)
    for y in range(0, H, 48 * s):
        d.line([(0, y), (W, y)], fill=(19, 25, 31), width=s)

    # left: the event stream (small rows)
    rows = [
        ("post_tool_call", "read_file  ~/.ssh/id_rsa", RED),
        ("post_tool_call", "web_extract  https://…/notes", AMBER),
        ("post_tool_call", "terminal  curl -d @key …", RED),
        ("post_approval", "deny  rm -rf /tmp/x", MUTED),
        ("subagent_start", "worker  “complete the step”", MUTED),
        ("post_api_request", "api.openai.com  812 tok", MUTED),
    ]
    x0, y0 = 56 * s, 150 * s
    rowh = 46 * s
    for i, (hook, what, tone) in enumerate(rows):
        y = y0 + i * rowh
        d.rounded_rectangle([x0, y, x0 + 380 * s, y + 36 * s], radius=8 * s, fill=PANEL, outline=LINE, width=s)
        d.ellipse([x0 + 12 * s, y + 13 * s, x0 + 22 * s, y + 23 * s], fill=tone)
        d.text((x0 + 32 * s, y + 7 * s), hook, font=font("mono", 11 * s), fill=MUTED)
        d.text((x0 + 32 * s, y + 20 * s), what, font=font("mono", 11 * s), fill=INK)

    # middle: flow lines into the knot
    kx, ky = 540 * s, 285 * s
    for i in range(len(rows)):
        y = y0 + i * rowh + 18 * s
        d.line([(x0 + 380 * s, y), (kx - 40 * s, ky)], fill=(40, 90, 100), width=2 * s)
    d.ellipse([kx - 26 * s, ky - 26 * s, kx + 26 * s, ky + 26 * s], outline=CYAN, width=3 * s, fill=BG)
    d.ellipse([kx - 10 * s, ky - 10 * s, kx + 10 * s, ky + 10 * s], fill=CYAN)
    d.text((kx - 38 * s, ky + 34 * s), "correlate", font=font("mono", 11 * s), fill=CYAN)

    # right: the finding card
    cx, cy, cw, ch = 640 * s, 160 * s, 500 * s, 250 * s
    d.rounded_rectangle([cx, cy, cx + cw, cy + ch], radius=12 * s, fill=PANEL, outline=CYAN, width=2 * s)
    d.line([(kx + 26 * s, ky), (cx, ky)], fill=CYAN, width=3 * s)
    d.text((cx + 20 * s, cy + 16 * s), "● HIGH", font=font("semi", 14 * s), fill=RED)
    d.text((cx + 92 * s, cy + 17 * s), "SL-001  ·  confidence medium", font=font("mono", 12 * s), fill=MUTED)
    d.text((cx + 20 * s, cy + 44 * s), "Sensitive access followed by egress", font=font("semi", 19 * s), fill=INK)
    d.text((cx + 20 * s, cy + 76 * s), "T1552.001  T1567  T1700", font=font("mono", 12 * s), fill=CYAN)
    ev = [("observed", "secret.access   read_file   ~/.ssh/id_rsa"), ("observed", "content.untrusted   web_extract"), ("inferred", "net.egress   terminal   127.0.0.1:8787")]
    for i, (vis, line) in enumerate(ev):
        y = cy + 108 * s + i * 26 * s
        d.text((cx + 20 * s, y), vis, font=font("mono", 11 * s), fill=CYAN if vis == "observed" else AMBER)
        d.text((cx + 96 * s, y), line, font=font("mono", 11 * s), fill=INK)
    d.line([(cx + 20 * s, cy + 196 * s), (cx + cw - 20 * s, cy + 196 * s)], fill=LINE, width=s)
    d.text((cx + 20 * s, cy + 208 * s), "→ OCSF 1.9  ·  syslog  ·  CEF  ·  Splunk HEC  ·  Elastic  ·  Wazuh", font=font("mono", 11 * s), fill=MUTED)

    # title
    d.text((56 * s, 48 * s), "SIEMless", font=font("bold", 54 * s), fill=INK)
    d.text((300 * s, 70 * s), "agent security telemetry for Hermes", font=font("reg", 22 * s), fill=MUTED)
    if tagline:
        d.text((56 * s, h * s - 70 * s), "Every tool call, file read, command, request, approval and subagent — as security events your SIEM already understands.",
               font=font("reg", 15 * s), fill=MUTED)
        d.text((56 * s, h * s - 42 * s), "A Salty Vet · a product of ASV Labs", font=font("semi", 13 * s), fill=CYAN)

    im = im.resize((w, h), Image.LANCZOS)
    out.parent.mkdir(parents=True, exist_ok=True)
    im.save(out, optimize=True)
    print(out, im.size)


if __name__ == "__main__":
    banner(1200, 600, ROOT / "docs" / "banner.png")
    banner(1280, 640, ROOT / "docs" / "social-preview.png")
    sys.exit(0)

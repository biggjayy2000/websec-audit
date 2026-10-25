#!/usr/bin/env python3
"""Turns captured terminal output and the Markdown report into portfolio-ready pages.

The terminal pages are not a mock-up: they contain the real bytes the CLI printed,
with its ANSI colour codes translated to CSS classes.
"""

from __future__ import annotations

import html
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
SHOTS = os.path.join(HERE, "shots")

ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")
SGR_CLASS = {
    "1;35": "sev-critical",
    "1;31": "sev-high",
    "1;33": "sev-medium",
    "1;36": "sev-low",
    "1;37": "sev-info",
    "2": "dim",
    "0": "",
}

TERMINAL_CSS = """
  * { box-sizing: border-box; }
  html, body { margin: 0; }
  body {
    background: #eef1f5;
    font-family: "Cascadia Mono", Consolas, "Courier New", monospace;
    padding: 26px 28px;
  }
  .window {
    background: #0d1117;
    border-radius: 10px;
    box-shadow: 0 18px 40px rgba(16, 24, 40, .28);
    overflow: hidden;
    border: 1px solid #1c2431;
  }
  .titlebar {
    display: flex; align-items: center; gap: 9px;
    background: #161d29; padding: 10px 14px; border-bottom: 1px solid #222c3a;
  }
  .dot { width: 11px; height: 11px; border-radius: 50%; }
  .dot.r { background: #ff5f57; } .dot.y { background: #febc2e; } .dot.g { background: #28c840; }
  .title { color: #8b98a9; font-size: 12px; margin-left: 8px; letter-spacing: .2px; }
  .screen {
    margin: 0; padding: 16px 18px 20px;
    color: #c9d1d9; font-size: 12.6px; line-height: 1.42;
    white-space: pre; overflow: hidden;
  }
  .sev-critical { color: #e879f9; font-weight: 700; }
  .sev-high { color: #ff7b72; font-weight: 700; }
  .sev-medium { color: #e3b341; font-weight: 700; }
  .sev-low { color: #56d4dd; font-weight: 700; }
  .sev-info { color: #d2d8e0; font-weight: 700; }
  .dim { color: #6e7d90; }
"""


def ansi_to_html(text: str) -> str:
    out, cls, pos = [], "", 0
    for match in ANSI_RE.finditer(text):
        out.append(_span(text[pos:match.start()], cls))
        cls = SGR_CLASS.get(match.group(1), "")
        pos = match.end()
    out.append(_span(text[pos:], cls))
    return "".join(out)


def _span(text: str, cls: str) -> str:
    if not text:
        return ""
    escaped = html.escape(text, quote=False)
    return f'<span class="{cls}">{escaped}</span>' if cls else escaped


def terminal_page(title: str, path: str, tail: int | None = None) -> str:
    with open(path, encoding="utf-8", errors="replace") as handle:
        raw = handle.read().replace("\r\n", "\n").rstrip("\n")
    if tail:
        raw = "\n".join(raw.split("\n")[-tail:])
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>{TERMINAL_CSS}</style></head>
<body>
<div class="window">
  <div class="titlebar">
    <span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
    <span class="title">{html.escape(title)}</span>
  </div>
  <pre class="screen">{ansi_to_html(raw)}</pre>
</div>
</body></html>"""


# ------------------------------------------------------------------ report ---
REPORT_CSS = """
  * { box-sizing: border-box; }
  html, body { margin: 0; background: #eef1f5; }
  body { font-family: "Segoe UI", Calibri, Arial, sans-serif; padding: 26px 28px; }
  .page {
    background: #fff; max-width: 880px; margin: 0 auto; padding: 44px 52px 40px;
    box-shadow: 0 18px 40px rgba(16, 24, 40, .16); border-radius: 10px;
    color: #1c2431; font-size: 13.4px; line-height: 1.55;
  }
  h1 { font-size: 23px; margin: 0 0 14px; letter-spacing: -.2px; }
  h2 { font-size: 15.5px; margin: 26px 0 10px; padding-bottom: 5px; border-bottom: 1px solid #e4e8ee; }
  h3 { font-size: 13.6px; margin: 20px 0 6px; }
  ul { margin: 4px 0 8px; padding-left: 20px; }
  li { margin-bottom: 3px; }
  code {
    font-family: "Cascadia Mono", Consolas, monospace; font-size: 11.6px;
    background: #f2f4f7; border: 1px solid #e3e7ed; border-radius: 4px; padding: 1px 4px;
    color: #2b3440;
  }
  table { border-collapse: collapse; margin: 8px 0 4px; font-size: 12.6px; }
  th, td { border: 1px solid #e1e6ec; padding: 5px 14px; text-align: left; }
  th { background: #f6f8fa; }
  .sev {
    font-size: 10.5px; font-weight: 700; padding: 2px 7px; border-radius: 999px;
    text-transform: uppercase; letter-spacing: .5px; margin-right: 6px; vertical-align: 1px;
  }
  .sev-high { background: #fde8e6; color: #b42318; }
  .sev-medium { background: #fdf1d6; color: #8a5a00; }
  .sev-low { background: #e6f4f6; color: #0e6b74; }
  .sev-critical { background: #f6e7fb; color: #8b1fa8; }
  .sev-info { background: #eef1f5; color: #445063; }
  .muted { color: #5b6675; }
  .num { color: #98a2b3; font-weight: 600; margin-right: 2px; }
"""

INLINE_CODE = re.compile(r"`([^`]+)`")
BOLD = re.compile(r"\*\*(.+?)\*\*")
SEVERITY_HEADING = re.compile(r"^(?:(\d+)\.\s*)?\[(Critical|High|Medium|Low|Info)\]\s*(.+)$")


def inline(text: str) -> str:
    escaped = html.escape(text, quote=False)
    escaped = INLINE_CODE.sub(lambda m: f"<code>{m.group(1)}</code>", escaped)
    return BOLD.sub(lambda m: f"<strong>{m.group(1)}</strong>", escaped)


def report_page(markdown_path: str, title: str) -> str:
    with open(markdown_path, encoding="utf-8") as handle:
        lines = handle.read().replace("\r\n", "\n").split("\n")

    body, in_ul, in_table = [], False, False

    def close_lists():
        nonlocal in_ul, in_table
        if in_ul:
            body.append("</ul>")
            in_ul = False
        if in_table:
            body.append("</tbody></table>")
            in_table = False

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("|"):
            if stripped.startswith("| ---"):
                continue
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if not in_table:
                close_lists()
                body.append("<table><thead><tr>" + "".join(f"<th>{inline(c)}</th>" for c in cells) + "</tr></thead><tbody>")
                in_table = True
            else:
                body.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in cells) + "</tr>")
            continue

        if stripped.startswith("### "):
            close_lists()
            heading = stripped[4:]
            match = SEVERITY_HEADING.match(heading)
            if match:
                number, level, text = match.groups()
                prefix = f'<span class="num">{number}.</span> ' if number else ""
                body.append(
                    f'<h3>{prefix}<span class="sev sev-{level.lower()}">{level}</span>{inline(text)}</h3>'
                )
            else:
                body.append(f"<h3>{inline(heading)}</h3>")
        elif stripped.startswith("## "):
            close_lists()
            body.append(f"<h2>{inline(stripped[3:])}</h2>")
        elif stripped.startswith("# "):
            close_lists()
            body.append(f"<h1>{inline(stripped[2:])}</h1>")
        elif stripped.startswith("- "):
            if in_table:
                close_lists()
            if not in_ul:
                body.append("<ul>")
                in_ul = True
            body.append(f"<li>{inline(stripped[2:])}</li>")
        elif not stripped:
            close_lists()
        else:
            close_lists()
            body.append(f'<p class="muted">{inline(stripped)}</p>')

    close_lists()

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>{REPORT_CSS}</style></head>
<body><div class="page">
{''.join(body)}
</div></body></html>"""


if __name__ == "__main__":
    os.makedirs(SHOTS, exist_ok=True)

    pages = {
        "terminal-scan.html": terminal_page("websec-audit - demo assessment", os.path.join(HERE, "terminal_ansi.txt")),
        "terminal-tests.html": terminal_page("websec-audit - test suite", os.path.join(HERE, "tests_ansi.txt"), tail=14),
        "report.html": report_page(os.path.join(HERE, "report-from-scan.md"), "websec-audit report"),
    }
    for name, content in pages.items():
        path = os.path.join(SHOTS, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        print("wrote", path)

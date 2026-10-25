# Portfolio assets

Screenshots generated from a real run of the tool, not mock-ups. The terminal pages contain the
exact bytes the CLI printed, with its ANSI colour codes translated to CSS.

| File | What it shows | Use it for |
| --- | --- | --- |
| `index.html` | The recruiter-facing page itself — headline, stats, three plain-English points, screenshots | Host it on GitHub Pages, or open it locally and print to PDF |
| `screenshots/terminal-scan.png` | Full assessment of the demo server: 17 findings, severity counts, quoted evidence | Portfolio hero image, README top, LinkedIn post |
| `screenshots/terminal-tests.png` | `Ran 53 tests ... OK` from the real test suite | Speaking to engineering rigour in interviews |
| `screenshots/report-top.png` | The generated Markdown report rendered: summary table and the first findings with remediation | Showing the deliverable, not just the scanner |
| `screenshots/report-full.png` | The entire report on one page | Drive portfolio, "full report" link |

Supporting files:

- `report-from-scan.md` — the report the screenshots were taken from
- `terminal_ansi.txt`, `tests_ansi.txt` — raw captured output
- `build_shots.py` — turns the captures into the pages that were screenshotted
- `shots/` — the intermediate HTML pages

## Before you publish

The page is self-contained (no CDN, no external fonts), so it works offline and from a `file://` path.
Two things to finish:

1. The **View the code** button is a placeholder — search for `TODO: point this at the repository` in
   `index.html` and replace the `href` with your repo URL.
2. The **Build writeup** button links to `../docs/WRITEUP.md`, which browsers download rather than render.
   Convert it to HTML or PDF alongside the page if you want it clickable.

## Regenerate

```bash
cd websec-audit

# 1. Real capture of a scan (keeps ANSI colours)
python examples/demo_server.py --port 8000 &
python -m websec_audit http://127.0.0.1:8000 --markdown portfolio/report-from-scan.md \
  > portfolio/terminal_ansi.txt 2>&1
python -m unittest discover -s tests -t . -v > portfolio/tests_ansi.txt 2>&1

# 2. Build the styled pages
python portfolio/build_shots.py
python -m http.server 8010 --bind 127.0.0.1 --directory portfolio/shots &

# 3. Screenshot them (Chrome, 2x for crisp text)
CHROME="/c/Program Files/Google/Chrome/Application/chrome.exe"
"$CHROME" --headless=new --hide-scrollbars --force-device-scale-factor=2 \
  --window-size=1240,936 --screenshot=portfolio/screenshots/terminal-scan.png \
  http://127.0.0.1:8010/terminal-scan.html
```

## Honest labelling

These are rendered captures of real terminal output, not photographs of a terminal window. If a
portfolio page implies otherwise, say "rendered from the tool's output" instead of "terminal
screenshot". The distinction is small but it is the kind of detail an interviewer may ask about.

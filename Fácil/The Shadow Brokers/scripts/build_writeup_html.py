#!/usr/bin/env python3
"""Genera una versión HTML autocontenida del writeup (imágenes embebidas)."""
import base64
import mimetypes
import re
from pathlib import Path

import markdown

BASE = Path(__file__).resolve().parent.parent
MD = BASE / "writeup_shadow_brokers.md"
HTML = BASE / "writeup_shadow_brokers.html"

text = MD.read_text(encoding="utf-8")


def embed(match: re.Match) -> str:
    alt, src = match.group(1), match.group(2)
    path = (BASE / src).resolve()
    if not path.is_file():
        return match.group(0)
    mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    data = base64.b64encode(path.read_bytes()).decode("ascii")
    return f'![{alt}](data:{mime};base64,{data})'


text = re.sub(r"!\[([^\]]*)\]\(([^)]+)\)", embed, text)
body = markdown.markdown(
    text,
    extensions=["tables", "fenced_code", "toc", "sane_lists"],
)

css = """
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
max-width:1100px;margin:2rem auto;padding:0 1.2rem;line-height:1.55;color:#1f2328;background:#fff}
h1,h2,h3{line-height:1.25;margin-top:1.8em}
h1{border-bottom:2px solid #d0d7de;padding-bottom:.3em}
h2{border-bottom:1px solid #d8dee4;padding-bottom:.25em}
code{background:#f6f8fa;padding:.15em .35em;border-radius:4px;font-size:.92em}
pre{background:#f6f8fa;padding:1em;border-radius:6px;overflow-x:auto;border:1px solid #d8dee4}
pre code{background:none;padding:0}
table{border-collapse:collapse;width:100%;margin:1em 0}
th,td{border:1px solid #d0d7de;padding:.45em .7em;text-align:left;vertical-align:top}
th{background:#f6f8fa}
img{max-width:100%;height:auto;border:1px solid #d0d7de;border-radius:6px;display:block;margin:1em auto}
em{color:#57606a}
blockquote{border-left:4px solid #d0d7de;margin:1em 0;padding:.2em 1em;color:#57606a;background:#f6f8fa}
"""

html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>The Shadow Brokers — Writeup</title>
<style>{css}</style>
</head>
<body>
{body}
</body>
</html>
"""

HTML.write_text(html, encoding="utf-8")
print(f"[+] {HTML} ({HTML.stat().st_size} bytes)")

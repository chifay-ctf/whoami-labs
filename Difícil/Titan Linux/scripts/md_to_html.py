#!/usr/bin/env python3
"""Convierte INFORME_FINAL.md a HTML autocontenido con imagenes embebidas."""
import base64
import mimetypes
import os
import re
import markdown

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MD = os.path.join(BASE, "writeup", "INFORME_FINAL.md")
HTML = os.path.join(BASE, "writeup", "INFORME_FINAL.html")

with open(MD, "r", encoding="utf-8") as f:
    text = f.read()

html_body = markdown.markdown(
    text,
    extensions=["tables", "fenced_code", "toc", "sane_lists", "nl2br"],
)

def embed(match):
    src = match.group(1)
    if src.startswith(("http://", "https://", "data:")):
        return match.group(0)
    path = os.path.normpath(os.path.join(BASE, "writeup", src))
    if not os.path.isfile(path):
        return match.group(0)
    mime = mimetypes.guess_type(path)[0] or "image/png"
    with open(path, "rb") as img:
        b64 = base64.b64encode(img.read()).decode("ascii")
    return f'src="data:{mime};base64,{b64}"'

html_body = re.sub(r'src="([^"]+)"', embed, html_body)

CSS = """
:root { --fg:#1f2937; --muted:#6b7280; --accent:#0f766e; --bg:#ffffff; --code:#f3f4f6; }
* { box-sizing: border-box; }
body { margin:0; background:#e5e7eb; color:var(--fg);
       font-family: 'DejaVu Sans', Arial, Helvetica, sans-serif; line-height:1.55; }
.page { max-width: 1100px; margin: 24px auto; background:var(--bg);
        padding: 48px 56px; box-shadow: 0 8px 30px rgba(0,0,0,.12); }
h1 { color:#0b3b36; border-bottom: 3px solid var(--accent); padding-bottom: 10px; }
h2 { color:#0f766e; margin-top: 34px; border-bottom: 1px solid #d1d5db; padding-bottom: 6px; }
h3 { color:#115e59; margin-top: 26px; }
h4 { color:#134e4a; }
a { color:#0f766e; }
code { background:var(--code); padding: 2px 5px; border-radius: 4px;
       font-family: 'DejaVu Sans Mono', Consolas, monospace; font-size: .92em; }
pre { background:#111827; color:#e5e7eb; padding: 14px 16px; border-radius: 8px;
      overflow-x: auto; border-left: 4px solid var(--accent); }
pre code { background: transparent; color: inherit; padding: 0; }
table { border-collapse: collapse; width: 100%; margin: 16px 0; font-size: .95em; }
th, td { border: 1px solid #d1d5db; padding: 8px 10px; text-align: left; vertical-align: top; }
th { background:#0f766e; color:#fff; }
tr:nth-child(even) td { background:#f9fafb; }
img { max-width: 100%; height: auto; display:block; margin: 14px auto;
      border: 1px solid #d1d5db; border-radius: 6px; box-shadow: 0 2px 10px rgba(0,0,0,.10); }
blockquote { border-left: 4px solid #f59e0b; background:#fffbeb; margin: 16px 0;
             padding: 10px 16px; color:#78350f; }
hr { border: none; border-top: 1px solid #d1d5db; margin: 28px 0; }
@media print {
  body { background:#fff; }
  .page { box-shadow:none; margin:0; padding: 16mm 12mm; max-width:none; }
  h2 { page-break-after: avoid; }
  pre, table, img { page-break-inside: avoid; }
  pre { white-space: pre-wrap; word-wrap: break-word; overflow: visible; font-size: 8.2pt; }
  code { word-break: break-word; }
  img { max-height: 150mm; }
}
"""

html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe de Auditoria - Titan Linux (CPENT Victim)</title>
<style>{CSS}</style>
</head>
<body>
<div class="page">
{html_body}
</div>
</body>
</html>
"""

with open(HTML, "w", encoding="utf-8") as f:
    f.write(html)

print(f"HTML generado: {HTML}")
print(f"Tamano: {os.path.getsize(HTML)/1024/1024:.2f} MB")

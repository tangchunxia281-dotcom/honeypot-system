"""Literal rendering for untrusted log/model text in downloadable Markdown."""
import html
import re


def literal(value):
    text=html.escape(str(value),quote=False)
    # Prevent log payloads from introducing active images/links, headings or
    # fenced code when a reader opens the downloaded Markdown in a rich viewer.
    return re.sub(r'([\\`*_{}\[\]()#+.!|~-])',r'\\\1',text)

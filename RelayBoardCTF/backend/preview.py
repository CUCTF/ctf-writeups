import re

from flask import current_app


def render_handoff_preview(text):
    def replace_include(match):
        snippet_name = match.group(1).strip()
        snippet_path = current_app.config["SNIPPET_DIR"] / snippet_name
        return snippet_path.read_text()

    return re.sub(r"\[\[include:(.+?)\]\]", replace_include, text)

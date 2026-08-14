# Configuration file for the Sphinx documentation builder.
#
# Run with:  sphinx-build -b html docs/ docs/_build/html
#            (from the python/ directory)

import os
import sys

# Make the linep package importable without installing it.
sys.path.insert(0, os.path.abspath(".."))

# ── Project information ──────────────────────────────────────────────────────
project   = "LiNeP"
copyright = "2026, LiNeP Authors"
author    = "LiNeP Authors"
release   = "1.0.0"

# ── Extensions ───────────────────────────────────────────────────────────────
extensions = [
    "sphinx.ext.autodoc",          # Extract docstrings from Python source.
    "sphinx.ext.autodoc.typehints", # Render type annotations in signatures.
    "sphinx.ext.napoleon",         # Google-style docstrings.
    "sphinx.ext.intersphinx",      # Links to Python stdlib docs.
    "sphinx.ext.viewcode",         # "View source" links in API docs.
    "myst_parser",                 # Markdown support (README inclusion).
]

# ── autodoc settings ─────────────────────────────────────────────────────────
autodoc_default_options = {
    "members":          True,
    "undoc-members":    False,
    "show-inheritance": True,
    "special-members":  "__init__",
}
autodoc_typehints          = "description"
autodoc_typehints_format   = "short"
autodoc_member_order       = "bysource"
add_module_names           = False   # shorter names in the rendered docs

# ── napoleon ─────────────────────────────────────────────────────────────────
napoleon_google_docstring          = True
napoleon_numpy_docstring           = False
napoleon_include_init_with_doc     = True
napoleon_use_rtype                 = False   # merge return type into Returns section

# ── intersphinx ──────────────────────────────────────────────────────────────
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# ── Output ───────────────────────────────────────────────────────────────────
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
html_theme       = "furo"
html_title       = f"LiNeP {release}"

html_theme_options = {
    "sidebar_hide_name":   False,
    "navigation_with_keys": True,
}

# ── MyST (Markdown) ───────────────────────────────────────────────────────────
myst_enable_extensions = ["colon_fence", "deflist"]
source_suffix = {
    ".rst": "restructuredtext",
    ".md":  "markdown",
}

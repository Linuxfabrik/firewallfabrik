# Configuration file for the Sphinx documentation builder.
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import datetime

project = 'FirewallFabrik'
copyright = '2016 - ' + str(datetime.datetime.now().year) + ' Linuxfabrik GmbH, Zurich, Switzerland'
author = 'Linuxfabrik GmbH, Zurich, Switzerland'

extensions = [
    'myst_parser',
]

source_suffix = {
    '.rst': 'restructuredtext',
    '.md': 'markdown',
}

templates_path = []
exclude_patterns = ['_build', 'source-code', 'Thumbs.db', '.DS_Store']

# -- Options for HTML output -------------------------------------------------

html_theme = 'sphinx_rtd_theme'
html_theme_options = {
    'collapse_navigation': False,
    'navigation_depth': 3,
}
html_static_path = []

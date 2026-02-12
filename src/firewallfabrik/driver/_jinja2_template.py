# Copyright (C) 2026 Linuxfabrik <info@linuxfabrik.ch>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# On Debian systems, the complete text of the GNU General Public License
# version 2 can be found in /usr/share/common-licenses/GPL-2.
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""Jinja2 template loader and renderer.

Follows the same resource resolution pattern as ``Configlet``:
check ``~/firewallfabrik/templates/<platform>/`` for user overrides
first, fall back to the package's ``resources/templates/<platform>/``
directory.
"""

from __future__ import annotations

import importlib.resources
from pathlib import Path

import jinja2


def _get_package_resources_dir() -> Path:
    """Return the path to the package's resources directory."""
    ref = importlib.resources.files('firewallfabrik') / 'resources'
    return Path(str(ref))


class Jinja2Template:
    """Load and render a Jinja2 template by platform and name."""

    def __init__(self, platform: str, template_name: str) -> None:
        search_paths: list[str] = []

        # User override directory (checked first)
        user_dir = Path.home() / 'firewallfabrik' / 'templates' / platform
        if user_dir.is_dir():
            search_paths.append(str(user_dir))

        # Package resources directory (fallback)
        pkg_dir = _get_package_resources_dir() / 'templates' / platform
        search_paths.append(str(pkg_dir))

        loader = jinja2.FileSystemLoader(search_paths)
        self._env = jinja2.Environment(
            loader=loader,
            undefined=jinja2.StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )
        self._template = self._env.get_template(template_name)

    def render(self, context: dict) -> str:
        """Render the template with the given context variables."""
        return self._template.render(context)

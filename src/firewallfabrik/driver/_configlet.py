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

"""Configlet template engine.

Supports:
- {{$var}} — variable substitution
- {{if var}}...{{endif}} — conditional blocks
- ## comment lines — removed before expansion
"""

from __future__ import annotations

import importlib.resources
import re
from pathlib import Path


def _get_package_resources_dir() -> Path:
    """Return the path to the package's resources directory."""
    ref = importlib.resources.files('firewallfabrik') / 'resources'
    return Path(str(ref))


class Configlet:
    """Template engine for configlet files."""

    _debugging: bool = False
    _begin_marker: str = '|||||||||||||||| Begin configlet {name}'
    _end_marker: str = '|||||||||||||||| End configlet {name}'

    def __init__(
        self,
        prefix: str,
        filename: str,
        default_prefix: str = '',
    ) -> None:
        self._name = filename
        self._prefix = prefix
        self._file_path = ''
        self._code: list[str] = []
        self._vars: dict[str, str] = {}
        self._remove_comments = True
        self._comment_str = '##'
        self._collapse_empty_strings = False

        if not self._reload(prefix, filename) and default_prefix:
            self._reload(default_prefix, filename)

    def _reload(self, prefix: str, filename: str) -> bool:
        self._prefix = prefix
        self._code = []

        file_path = self._get_configlet_path(prefix, filename)
        self._file_path = str(file_path)

        if not file_path.exists():
            return False

        text = file_path.read_text(encoding='utf-8', errors='replace')
        self._code = text.splitlines()
        return True

    def _get_configlet_path(self, prefix: str, filename: str) -> Path:
        p = Path(filename)
        if p.is_absolute():
            return p

        # Check home directory first (user overrides)
        home = Path.home()
        user_path = home / 'firewallfabrik' / 'configlets' / prefix / filename
        if user_path.exists():
            return user_path

        # Package resources
        return _get_package_resources_dir() / 'configlets' / prefix / filename

    def clear(self) -> None:
        self._vars.clear()
        self._remove_comments = True
        self._comment_str = '##'
        self._collapse_empty_strings = False

    def set_variable(self, name: str, value: str | int | bool) -> None:
        if isinstance(value, bool):
            self._vars[name] = '1' if value else '0'
        elif isinstance(value, int):
            self._vars[name] = str(value)
        else:
            self._vars[name] = value.strip()

    def remove_comments(self, comment_str: str = '##') -> None:
        self._remove_comments = True
        self._comment_str = comment_str

    def collapse_empty_strings(self, flag: bool) -> None:
        self._collapse_empty_strings = flag

    def expand(self) -> str:
        # Remove comment lines
        if self._remove_comments:
            lines = [
                line for line in self._code if not line.startswith(self._comment_str)
            ]
        else:
            lines = list(self._code)

        all_code = '\n'.join(lines)

        # Substitute {{$var}}
        var_re = re.compile(r'\{\{\$([^}]*)\}\}')
        counter = 0
        while counter < 1000:
            m = var_re.search(all_code)
            if not m:
                break
            var_name = m.group(1)
            if var_name in self._vars:
                all_code = all_code.replace(
                    f'{{{{${var_name}}}}}', self._vars[var_name]
                )
            else:
                # Replace {{$var}} with {{var}} for debugging
                all_code = all_code.replace(
                    f'{{{{${var_name}}}}}', f'{{{{{var_name}}}}}'
                )
            counter += 1

        # Process {{if var}}...{{endif}}
        counter = 0
        while counter < 1000:
            result = self._process_if(all_code)
            if result is None:
                break
            all_code = result
            counter += 1

        # Add debug markers
        if self._debugging:
            begin = self._begin_marker.format(name=self._name)
            end = self._end_marker.format(name=self._name)
            all_code = f'{begin}\n{all_code}{end}\n'

        # Collapse empty strings
        if self._collapse_empty_strings:
            lines = [line for line in all_code.split('\n') if line.strip()]
            all_code = '\n'.join(lines)

        return all_code

    def _process_if(self, stream: str) -> str | None:
        """Process one {{if var}}...{{endif}} block (innermost first)."""
        if_re = re.compile(r'\{\{if\s+([^}]+)\}\}')
        endif_re = re.compile(r'\{\{endif\}\}')

        if_matches = list(if_re.finditer(stream))
        if not if_matches:
            return None

        # Find innermost if (one whose body contains no other if)
        for if_match in reversed(if_matches):
            if_end = if_match.end()
            var_name = if_match.group(1).strip()

            # Find matching endif
            endif_match = endif_re.search(stream, if_end)
            if endif_match is None:
                continue

            # Check if there's another if between this if and endif
            nested_if = if_re.search(stream, if_end)
            if nested_if and nested_if.start() < endif_match.start():
                continue  # Not innermost

            if_start = if_match.start()
            endif_end = endif_match.end()
            body = stream[if_end : endif_match.start()]

            # Evaluate condition
            replacement = ''
            if var_name in self._vars:
                try:
                    val = int(self._vars[var_name])
                    if val:
                        replacement = body
                except ValueError:
                    if self._vars[var_name]:
                        replacement = body

            return stream[:if_start] + replacement + stream[endif_end:]

        return None

    @staticmethod
    def set_debugging(flag: bool) -> None:
        Configlet._debugging = flag

    @staticmethod
    def find_generated_text(
        configlet_name: str,
        text: str,
        nth: int = 1,
    ) -> str:
        begin = Configlet._begin_marker.format(name=configlet_name) + '\n'
        end = Configlet._end_marker.format(name=configlet_name) + '\n'

        count = 0
        pos = 0
        while count < nth:
            pos = text.find(begin, pos)
            if pos == -1:
                return ''
            count += 1
            if count < nth:
                pos += 1

        start = pos + len(begin)
        end_pos = text.find(end, start)
        if end_pos == -1:
            return text[start:]
        return text[start:end_pos]

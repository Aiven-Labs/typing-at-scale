#!/usr/bin/env python3
# Copyright (c) 2023 Aiven, Helsinki, Finland. https://aiven.io/
"""Get mypy statistics for the whole tree - or todo list for a team (-t).

Usage:

python3 -m misc.mypy_report

or

python3 -m misc.mypy_report -t andromeda

( per-team todo list )

The reported figure now is number of # type: ignore's.

"""

from aiven.shared.utils import REPOSITORY_ROOT
from aiven.utils.codeowners import CodeOwners, CodeOwnersEntry
from collections.abc import Collection, Iterator
from functools import cached_property
from pathlib import Path
from tabulate import tabulate
from typing import Any

import json
import subprocess

SLOC_HEADERS = ["owner", "#sloc", "ignores", "Anys", "#todo"]
FILE_HEADERS = SLOC_HEADERS.copy()
FILE_HEADERS[1] = "#file"

SlocEntry = list[Any]  # used for tabulate

CODEOWNERS_PATH = REPOSITORY_ROOT / ".github/CODEOWNERS"


def convert_mypy_module_to_path_re(s: str) -> str:
    if "." not in s:
        # Special snowflake case: non python module hierarchy member that can be .. anywhere.
        return "(?:.*/)?" + s + r"\.py$"

    # A pattern of the form qualified_module_name matches only the
    # named module, while dotted_module_name.* matches
    # dotted_module_name and any submodules (so foo.bar.* would match
    # all of foo.bar, foo.bar.baz, and foo.bar.baz.quux).
    if s.startswith("*."):
        return "(?:.*/)?" + convert_mypy_module_to_path_re(s.removeprefix("*."))

    # Stuff in the middle can be 'whatever'
    s = s.replace(".", "/")

    # .*. (rewritten to /*/) means arbitrary 0-N component match
    s = s.replace("/*/", "(?:/.*)?/")

    # Wildcard at end covers both the module itself, as well as any submodules.
    if s.endswith("/*"):
        s = s.removesuffix("/*")

        # This can be just that particular Python module, or something within
        return s + r"(?:/.*|)\.py$"

    # If we just hit the module, that's fine too
    return s + r"(?:/[^/]+|)\.py$"


def convert_mypy_modules_to_path_re(modules: list[str]) -> str:
    sl = [convert_mypy_module_to_path_re(s) for s in modules]
    if len(sl) == 1:
        return sl[0]
    s = "|".join(sl)
    return f"({s})"


def get_sloccount(path: str) -> Iterator[tuple[Path, int]]:
    root_absolute = Path(path).resolve()
    tokei_output = subprocess.run(["tokei", "-t=Python", "-o=json", root_absolute], check=True, stdout=subprocess.PIPE)
    sloc_data = json.loads(tokei_output.stdout)
    for file_sloc in sloc_data["Python"]["reports"]:
        relative_path = Path(file_sloc["name"]).relative_to(root_absolute)
        yield relative_path, file_sloc["stats"]["code"]


def _ripgrep_count(path: str, regex: str) -> Iterator[tuple[Path, int]]:
    root_absolute = Path(path).resolve()
    try:
        rg_output = subprocess.run(
            ["rg", "--count", "--with-filename", regex, root_absolute], check=True, stdout=subprocess.PIPE, text=True
        )
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            # no match
            return
        raise
    for line in rg_output.stdout.splitlines():
        name, count = line.split(":", 1)
        relative_path = Path(name).relative_to(root_absolute)
        yield relative_path, int(count)


def get_type_ignore_counts(path: str) -> Iterator[tuple[Path, int]]:
    yield from _ripgrep_count(path, "# (type: ignore|noqa)")


def get_any_counts(path: str) -> Iterator[tuple[Path, int]]:
    yield from _ripgrep_count(path, "[^a-zA-Z]Any([^a-zA-Z]|$)")


class Report:
    def __init__(self, *, grep: str | None, grep_negative: str | None):
        self.grep = grep
        self.grep_negative = grep_negative

    @cached_property
    def owners(self) -> CodeOwners:
        return CodeOwners(CODEOWNERS_PATH)

    @cached_property
    def any_dict(self) -> dict[Path, int]:
        return {k: v for k, v in get_any_counts(".") if self._is_covered_file(k)}

    @cached_property
    def sloc_dict(self) -> dict[Path, int]:
        return {k: v for k, v in get_sloccount(".") if self._is_covered_file(k)}

    @cached_property
    def ignores_dict(self) -> dict[Path, int]:
        return {k: v for k, v in get_type_ignore_counts(".") if self._is_covered_file(k)}

    def _is_covered_file(self, path: Path) -> bool:
        return (self.grep is None or self.grep in str(path)) and (
            self.grep_negative is None or self.grep_negative not in str(path)
        )

    def _sloc_by_team(self, team: str) -> Iterator[tuple[Path, int]]:
        for path, sloc in self.sloc_dict.items():
            if team:
                entry = self.owners.find(path)
                if not entry:
                    continue
                # substring match of owner; this could be faster but this is fast enough
                if not any(team in owner for owner in entry.owners):
                    continue
            yield path, sloc

    def files_by_team(self, team: str) -> Iterator[tuple[int, int, int, Path]]:
        """Return ignores, anys, sloc, path for a team."""
        for path, sloc in self._sloc_by_team(team):
            ignores = self.ignores_dict.get(path, 0)
            anys = self.any_dict.get(path, 0)
            yield ignores, anys, sloc, path

    def sloc_by_owner(self, by_file: bool, percent: bool) -> Collection[SlocEntry]:
        owned_sloc: dict[str, SlocEntry] = {}
        used_entries: set[CodeOwnersEntry] = set()
        path_strs = set()
        for path, sloc in self.sloc_dict.items():
            ignores = self.ignores_dict.get(path, 0)
            anys = self.any_dict.get(path, 0)
            path_strs.add(str(path))
            co_entry = self.owners.find(path)
            eowners: tuple[str, ...] = ("not assigned",)
            if co_entry:
                used_entries.add(co_entry)
                if co_entry.owners:
                    eowners = co_entry.owners
            if by_file:
                sloc = 1
            for owner, divisor in [("any", 1)] + [(owner, len(eowners)) for owner in eowners]:
                # 1 = sloc
                sloc_entry = owned_sloc.setdefault(owner, [owner] + [0] * (len(SLOC_HEADERS) - 1))
                sloc_entry[1] += max(1, sloc // divisor)
                # 2 = ignores
                ignores = max(1, ignores // divisor)
                sloc_entry[2] += ignores
                # 3 = anys
                anys = max(1, anys // divisor)
                sloc_entry[3] += anys

                # todo column
                sloc_entry[4] += ignores + anys

        unused_entries = sorted(set(self.owners.data) - used_entries)
        if unused_entries:
            for entry in unused_entries:
                for invalid in ["ci/", "deps/", "ui/", ".sh", "Jenkinsfile"]:
                    if invalid in entry.pathglob:
                        # Probably not interesting for Python sloc driven stuff
                        break
                else:
                    if "*" in entry.pathglob and not self.grep and not self.grep_negative:
                        print("Unused wildcard entry", entry)
                    elif entry.pathglob in path_strs:
                        override = self.owners.find(entry.pathglob)
                        if override and override.owners == entry.owners:
                            # Probably fine but inefficient
                            continue
                        print("Overridden? entry", entry, override)

        if percent:
            # Post process the non-summary to be percents
            for values in owned_sloc.values():
                for i in range(2, len(values)):
                    values[i] = "%.2f%%" % (100 * values[i] / values[1])

        return owned_sloc.values()

    def validate_codeowners(self) -> bool:
        # As the entries themselves may be painful to identify which
        # overlaps which, we do something even simpler: Look at EVERY
        # file in the tree, and identify those which have multiple
        # entries that have definitions in which the terminal
        # definition is missing some of the earlier ones.
        missing_owners: list[Path] = []
        override_by_path: dict[Path, CodeOwnersEntry] = {}
        used_entries: dict[CodeOwnersEntry, list[Path]] = {}
        broken_entries: dict[CodeOwnersEntry, list[tuple[CodeOwnersEntry, Path]]] = {}
        # team-arch is the ultimate fallback
        # team-release-engineering wants to own .BUILD
        # team-security wants to own deps/ by default, and due to that every other team 'conflicts' over it
        fallback_teams = {"@aiven/team-arch", "@aiven/team-security", "@aiven/team-release-engineering"}
        all_paths = set(self.sloc_dict.keys())
        for entry in self.owners.data:
            all_paths = all_paths | set(Path(".").glob(entry.pathglob))

        for path in sorted(all_paths):
            owners = list(self.owners.find_all(path))
            if not owners:
                missing_owners.append(path)
                continue
            active_owner = owners[-1]
            used_entries.setdefault(active_owner, []).append(path)
            if len(owners) < 2:
                continue
            overridden_owner = owners[-2]
            override_by_path[path] = overridden_owner
            active_teams = active_owner.owner_set
            missing_teams = overridden_owner.owner_set - active_teams - fallback_teams
            if not active_teams or missing_teams:
                broken_entries.setdefault(active_owner, []).append((overridden_owner, path))

        ok = True

        # See if any of the entries don't prove added value
        for owner, paths in sorted(used_entries.items()):
            # Type checker makes this bit lame, oh well
            #
            # If there is no override, this does provide value
            if any(path not in override_by_path for path in paths):
                continue

            # Otherwise, check if one of the overrides is useful
            overrides = set(override_by_path[path] for path in paths)
            if any(override.owner_set != owner.owner_set for override in overrides):
                continue
            print("Redundant", owner, paths)
            # This isn't strictly speaking fatal

        # We don't need directories to be owned
        missing_owners = [p for p in missing_owners if not Path(p).is_dir()]
        if missing_owners:
            print()
            print(f"{len(missing_owners)} files missing matching entry:")
            for path in sorted(missing_owners):
                # Print entries that can be inserted to CODEOWNERS
                print(f"/{path}")
            ok = False

        unused_entries = {
            entry for entry in set(self.owners.data) - set(used_entries.keys()) if not Path(entry.pathglob).is_dir()
        }
        if unused_entries:
            print()
            print(f"{len(unused_entries)} unused codeowners entries:")
            for entry in sorted(unused_entries):
                print("Unused", entry)
                print()
            ok = False

        if broken_entries:
            print()
            for entry, files in sorted(broken_entries.items()):
                print("Override", entry, files)
                print()
            ok = False

        return ok


def main() -> int:
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("--grep", "-g", help="List files for specific substring")
    parser.add_argument("--grep-negative", "-G", help="List files not matching specific substring")
    parser.add_argument("--percent", "-p", action="store_true", help="Show percents")
    parser.add_argument("--team", "-t", help="Team to list files for")
    parser.add_argument(
        "--validate-codeowners", action="store_true", help="Validate that codeowners definitions are sensible"
    )
    args = parser.parse_args()
    report = Report(grep=args.grep, grep_negative=args.grep_negative)

    if args.validate_codeowners:
        return 0 if report.validate_codeowners() else 1

    if args.team:
        print("ignores | anys | sloc | path - 'anys' count is approximate due to regex parsing.")
        for result in sorted(report.files_by_team(args.team), key=lambda x: (x[0], x[1], x[2], x[3])):
            print(*result)
        return 0
    owned_sloc = report.sloc_by_owner(True, args.percent)
    print(tabulate(sorted(owned_sloc, key=lambda x: x[1]), headers=FILE_HEADERS, tablefmt="github"))
    owned_sloc = report.sloc_by_owner(False, args.percent)
    print(tabulate(sorted(owned_sloc, key=lambda x: x[1]), headers=SLOC_HEADERS, tablefmt="github"))
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())

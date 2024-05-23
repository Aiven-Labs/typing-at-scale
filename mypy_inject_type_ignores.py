#!/usr/bin/env python3
# Copyright (c) 2023 Aiven, Helsinki, Finland. https://aiven.io/
from collections import defaultdict
from collections.abc import Iterator
from itertools import groupby
from pathlib import Path
from pydantic import BaseModel, validator
from typing import IO

import re
import sys

ERROR_REGEX = re.compile(r"^(?P<filename>.+?):(?P<line_number>\d+): error: (?P<message>.+)  ?\[(?P<code>.+)\]\s*$")
# COMMENT_REGEX = re.compile(r"  # type: ignore(.+)$")
COMMENT_REGEX = re.compile(
    r"^(?P<pre_comments>.+?)(?P<preceding_comments>|#[^\\]+  )# type: ignore(?P<codes>(?!\[)|\[[\w-]+\])(?P<remaining_comments>.*)$"
)

NEW_COMMENT = "# type: ignore[{comma_codes}]"

SEPARATE_COMMENTS_REGEX = re.compile(r"(?P<quoted>\".*?\"|\'.*?\')|(?P<comment>#[^#]+)")

CODE_REGEX = re.compile(r"^[a-z][-a-z]+[a-z]$")


class Error(BaseModel):
    line_number: int
    message: str
    code: str

    @validator("code")
    @classmethod
    def validate_code(cls, v: str) -> str:
        if CODE_REGEX.match(v):
            return v
        else:
            raise ValueError(f"{v!r} does not meet the expected syntax for a mypy error code.")


class SourceFile(BaseModel):
    filename: Path
    errors: list[Error]

    def get_errors(self, threshold: int) -> tuple[set[str], list[Error]]:
        """Returns the error codes occuring more than the threhold number of times,
        along with the details of the other error codes.
        """
        total_occurances: dict[str, int] = defaultdict(int)
        for error in self.errors:
            total_occurances[error.code] += 1
        exceeded_threshold = {code for code, count in total_occurances.items() if count > threshold}
        return exceeded_threshold, [error for error in self.errors if error.code not in exceeded_threshold]


def get_mypy_output_lines(source: IO[str]) -> Iterator[str]:
    for line in source:
        line = line.strip()
        if line:
            yield line


def get_errors(source: IO[str]) -> Iterator[SourceFile]:
    matches = (match.groupdict() for match in map(ERROR_REGEX.match, get_mypy_output_lines(source)) if match)
    for filename, match_dicts in groupby(matches, key=lambda match: match["filename"]):
        errors = []
        for match_dict in match_dicts:
            del match_dict["filename"]
            errors.append(Error(**match_dict))
        yield SourceFile(filename=filename, errors=errors)


def handle_line(*, error: Error, line: str) -> str:
    initial_comment_offset: int | None = None
    earlier_comments: list[str] = []
    type_ignore_part: str | None = None
    later_comments: list[str] = []

    for part in SEPARATE_COMMENTS_REGEX.finditer(line):
        if comment := part.groupdict().get("comment"):
            if initial_comment_offset is None:
                initial_comment_offset = part.span()[0]
            if comment.replace(" ", "").startswith("#type:ignore"):
                type_ignore_part = comment[1:].strip()
            elif type_ignore_part is None:
                earlier_comments.append(comment.strip())
            else:
                later_comments.append(comment.strip())

    error_message_comment = "# " + error.message.rstrip()
    codes: set[str] = set()
    if error.code == "unused-ignore":
        if error_message_comment in later_comments:
            later_comments.remove(error_message_comment)
        comments = earlier_comments + later_comments
        return (line[:initial_comment_offset] + "  ".join(comments)).rstrip()

    if type_ignore_part is not None and "[" in type_ignore_part:
        # get what's between [ and ]
        preexisting_codes = type_ignore_part.split("[", 1)[1][:-1]
        codes = set(preexisting_codes.split(","))

    if error.code in codes:
        return line  # no need to change anything

    codes.add(error.code)
    comma_codes = ",".join(sorted(codes))
    if initial_comment_offset is None:
        return line + "  " + NEW_COMMENT.format(comma_codes=comma_codes) + "  " + error_message_comment
    other_comments = earlier_comments + later_comments
    other_comments.insert(0, error_message_comment)
    comments = [NEW_COMMENT.format(comma_codes=comma_codes)] + other_comments
    return line[:initial_comment_offset] + "  ".join(comments)


def handle_source_file(source_file: SourceFile) -> int:
    with open(source_file.filename) as handle:
        file_lines = handle.read().split("\n")
    modifications: int = 0
    module_wide_ignores, errors = source_file.get_errors(threshold=999)
    for error in errors:
        line = file_lines[error.line_number - 1]
        new_line = handle_line(line=line, error=error)

        if new_line is not None and new_line != line:
            file_lines[error.line_number - 1] = new_line
            modifications += 1
    if module_wide_ignores:
        print(f"Ignoring all errors of type {module_wide_ignores} in {source_file.filename}")
        comma_codes = ",".join(sorted(module_wide_ignores))
        file_lines.insert(1, NEW_COMMENT.format(comma_codes=comma_codes))
        modifications += 1
    if modifications > 0:
        print(f"Rewriting {source_file.filename} with {modifications} changes.")
        with open(source_file.filename, "w") as handle:
            handle.write("\n".join(file_lines))
    return modifications


def main(mypy_output_filename: str) -> int:
    modified_files: int = 0
    with open(mypy_output_filename) as source:
        for source_file in get_errors(source=source):
            if handle_source_file(source_file) > 0:
                modified_files += 1
    if modified_files:
        print(f"Modified {modified_files}.")
        return 1
    print("No files required modification.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

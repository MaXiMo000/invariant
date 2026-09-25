"""export_contains check: does a data export actually contain every category
it promises? (Formerly the standalone `portable-evidence` tool.)

A privacy policy or an export feature's own docs say "your export includes
your profile, your order history, and your uploaded photos." This checks a
real export against that declared list, category by category -- and a
category that exists but is empty ("", [], {}, null, a header-only CSV)
counts as missing: the point is proving real data landed.

Args:
    export: a JSON file, a directory, or a .zip (e.g. a Google-Takeout-style
        archive, extracted to a scratch directory first)
    categories: a list of
        {name, json_path, min_count?}             -- against a JSON file export
        {name, file_glob}                         -- against a directory/zip export
        {name, file_glob, csv_column, min_count?} -- and that column has real values
      json_path is dot keys and [N] indices ("orders[0].id"), nothing more.

Status: fail if any category is missing; unverified if none is missing but
some couldn't be checked (the wrong export shape for what it needs); pass
only if every category was found.
"""
from __future__ import annotations

import contextlib
import csv
import json
import pathlib
import re
import tempfile
import zipfile

from ..model import FAIL, PASS, UNVERIFIED

FOUND, MISSING = "found", "missing"
_EMPTY = (None, "", [], {})
_SEGMENT = re.compile(r"([^.\[\]]+)|\[(\d+)\]")
# An export is someone else's archive: cap what extraction may write, so a
# zip bomb is a clear unverified, not a full disk.
MAX_UNZIPPED_BYTES = 2 * 1024**3


class _PathError(Exception):
    pass


def _resolve(document, path: str):
    current, walked = document, ""
    for key, index in _SEGMENT.findall(path):
        if key:
            walked += ("." if walked else "") + key
            if not isinstance(current, dict) or key not in current:
                raise _PathError(f"'{walked}' does not exist")
            current = current[key]
        else:
            walked += f"[{index}]"
            if not isinstance(current, list) or int(index) >= len(current):
                raise _PathError(f"'{walked}' does not exist")
            current = current[int(index)]
    return current


def _json_category(cat: dict, document) -> tuple[str, str]:
    name, path = cat["name"], cat["json_path"]
    try:
        value = _resolve(document, path)
    except _PathError as exc:
        return MISSING, f"'{name}': {exc}"
    min_count = cat.get("min_count")
    if min_count is not None:
        if not isinstance(value, list):
            return MISSING, f"'{name}': {path} is not a list, so min_count can't apply"
        if len(value) < min_count:
            return MISSING, f"'{name}': {path} has {len(value)} item(s), expected at least {min_count}"
        return FOUND, f"'{name}': {path} has {len(value)} item(s)"
    if value in _EMPTY:
        return MISSING, f"'{name}': {path} exists but is empty"
    return FOUND, f"'{name}': {path} is present"


def _file_category(cat: dict, export_dir: pathlib.Path) -> tuple[str, str]:
    name, pattern = cat["name"], cat["file_glob"]
    matches = sorted(p for p in export_dir.glob(pattern) if p.is_file() and p.stat().st_size > 0)
    if not matches:
        return MISSING, f"'{name}': no non-empty file matches '{pattern}'"
    column = cat.get("csv_column")
    if column is None:
        return FOUND, f"'{name}': {len(matches)} file(s) match '{pattern}'"
    min_count = cat.get("min_count", 1)
    try:
        with open(matches[0], newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if column not in (reader.fieldnames or []):
                return MISSING, f"'{name}': no column '{column}' in {matches[0].name}"
            filled = sum(1 for row in reader if (row.get(column) or "").strip())
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return MISSING, f"'{name}': could not read {matches[0].name} as CSV ({exc})"
    if filled < min_count:
        return MISSING, (f"'{name}': column '{column}' in {matches[0].name} has {filled} "
                         f"non-empty value(s), expected at least {min_count}")
    return FOUND, f"'{name}': column '{column}' in {matches[0].name} has {filled} non-empty value(s)"


def _check_all(categories: list, document, export_dir) -> list[dict]:
    results = []
    for cat in categories:
        name = cat.get("name", "<unnamed>")
        if "json_path" in cat and document is not None:
            status, detail = _json_category(cat, document)
        elif "file_glob" in cat and export_dir is not None:
            status, detail = _file_category(cat, export_dir)
        elif "json_path" in cat or "file_glob" in cat:
            needs = "a JSON file export" if "json_path" in cat else "a directory or zip export"
            status, detail = UNVERIFIED, f"'{name}' needs {needs}, which this export isn't"
        else:
            status, detail = UNVERIFIED, f"'{name}' declares neither json_path nor file_glob"
        results.append({"name": name, "status": status, "detail": detail})
    return results


def run(args: dict) -> tuple[str, str, dict]:
    export = pathlib.Path(args["export"])
    categories = args.get("categories") or []
    evidence = {"export": str(export)}
    if not categories:
        return UNVERIFIED, "no categories declared -- nothing to verify", evidence
    if not export.exists():
        return FAIL, f"{export} does not exist", evidence

    with contextlib.ExitStack() as stack:
        document = export_dir = None
        if export.is_dir():
            export_dir = export
        elif zipfile.is_zipfile(export):
            try:
                with zipfile.ZipFile(export) as zf:
                    size = sum(i.file_size for i in zf.infolist())
                    if size > MAX_UNZIPPED_BYTES:
                        return UNVERIFIED, (f"{export} would unzip to {size} bytes, over the "
                                            f"{MAX_UNZIPPED_BYTES}-byte cap"), evidence
                    tmp = stack.enter_context(tempfile.TemporaryDirectory(prefix="invariant-export-"))
                    zf.extractall(tmp)  # extractall strips absolute paths and ".." itself
            except zipfile.BadZipFile as exc:
                return UNVERIFIED, f"{export} is not a readable zip ({exc})", evidence
            export_dir = pathlib.Path(tmp)
        else:
            try:
                document = json.loads(export.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                return UNVERIFIED, f"{export} is not readable JSON ({exc})", evidence
        results = _check_all(categories, document, export_dir)

    evidence["categories"] = results
    missing = [r["name"] for r in results if r["status"] == MISSING]
    unchecked = [r["name"] for r in results if r["status"] == UNVERIFIED]
    found = len(results) - len(missing) - len(unchecked)
    if missing:
        return FAIL, f"{len(missing)} of {len(results)} categories missing: {', '.join(missing)}", evidence
    if unchecked:
        return UNVERIFIED, f"{found} found, {len(unchecked)} couldn't be checked: {', '.join(unchecked)}", evidence
    return PASS, f"all {found} categories present", evidence

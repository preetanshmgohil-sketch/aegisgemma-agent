"""Target ingestion: turns uploads (files, archives, folders) into TargetFiles."""

from __future__ import annotations

import io
import os
import zipfile
from pathlib import PurePosixPath

from .security_engine import MAX_FILE_BYTES, TargetFile

MAX_TOTAL_BYTES = 25 * 1024 * 1024
MAX_FILES = 400

TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".rb",
    ".php", ".rs", ".c", ".h", ".cpp", ".cc", ".cs", ".sh", ".bash", ".yaml",
    ".yml", ".json", ".md", ".tf", ".tfvars", ".sql", ".html", ".css", ".xml",
    ".toml", ".ini", ".cfg", ".conf", ".env", ".properties", ".gradle", ".txt",
}

TEXT_NAMES = {"dockerfile", "makefile", "procfile", "requirements.txt", ".env"}


def _is_probably_text(data: bytes) -> bool:
    if b"\x00" in data[:4096]:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _looks_like_text_path(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    if name in TEXT_NAMES or name.startswith("dockerfile"):
        return True
    suffix = PurePosixPath(path).suffix.lower()
    return suffix in TEXT_SUFFIXES


def _safe_relative_path(path: str) -> str:
    """Normalise an archive member path, refusing traversal outside the root."""
    cleaned = PurePosixPath(path.replace("\\", "/"))
    parts = [p for p in cleaned.parts if p not in (".", "/", "..")]
    if not parts:
        return "unnamed"
    return "/".join(parts)


def files_from_zip(data: bytes) -> list[TargetFile]:
    out: list[TargetFile] = []
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if len(out) >= MAX_FILES:
                break
            path = _safe_relative_path(info.filename)
            if total + info.file_size > MAX_TOTAL_BYTES:
                break
            if not _looks_like_text_path(path):
                continue
            try:
                raw = archive.read(info)
            except Exception:
                continue
            if not _is_probably_text(raw):
                continue
            if len(raw) > MAX_FILE_BYTES:
                raw = raw[:MAX_FILE_BYTES]
            total += len(raw)
            out.append(
                TargetFile(
                    path=path,
                    content=raw.decode("utf-8", errors="replace"),
                    size=len(raw),
                )
            )
    return out


def files_from_upload(filename: str, data: bytes) -> list[TargetFile]:
    if filename.lower().endswith(".zip"):
        return files_from_zip(data)
    if not _is_probably_text(data):
        return []
    content = data.decode("utf-8", errors="replace")
    if len(content) > MAX_FILE_BYTES:
        content = content[:MAX_FILE_BYTES]
    return [TargetFile(path=_safe_relative_path(filename), content=content, size=len(data))]


def files_from_directory(root: str) -> list[TargetFile]:
    out: list[TargetFile] = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if d not in {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
        ]
        for filename in filenames:
            if len(out) >= MAX_FILES:
                return out
            full = os.path.join(dirpath, filename)
            rel = _safe_relative_path(os.path.relpath(full, root))
            if not _looks_like_text_path(rel):
                continue
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if total + size > MAX_TOTAL_BYTES:
                return out
            try:
                with open(full, "rb") as handle:
                    raw = handle.read(MAX_FILE_BYTES)
            except OSError:
                continue
            if not _is_probably_text(raw):
                continue
            total += len(raw)
            out.append(
                TargetFile(
                    path=rel,
                    content=raw.decode("utf-8", errors="replace"),
                    size=len(raw),
                )
            )
    return out

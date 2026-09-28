"""Mac-to-Autopsy Triage & Disk-Imaging Collector.

Run with:  python3 -m streamlit run mac_to_autopsy_triage.py

This educational tool performs authorized logical collection from mounted media
or a verified raw image of an approved external physical disk. It never unlocks
devices, bypasses encryption, or writes commands to an evidence source.
"""

from __future__ import annotations

import hashlib
import os
import plistlib
import re
import shutil
import subprocess
import sys
from html import escape
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

import streamlit as st


APP_TITLE = "Digital Evidence Collector for Autopsy"
APP_VERSION = "0.2.0"
SCRIPT_DIR = Path(__file__).resolve().parent
CHUNK_SIZE = 8 * 1024 * 1024
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv"}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".heic", ".tif", ".tiff", ".gif"}
VIDEO_EXTENSIONS = {".mp4", ".mov", ".m4v", ".avi", ".mkv", ".webm"}
BROWSER_DATABASES = {"history.db", "history", "places.sqlite"}
ARTIFACT_OPTIONS = ["Documents", "Images", "Browser History Databases"]
MOBILE_ARTIFACT_OPTIONS = ["Documents", "Photos", "Videos"]


def default_output_root() -> Path:
    """Keep case data outside a read-only packaged application bundle."""
    if getattr(sys, "frozen", False):
        return Path.home() / "Digital Evidence Collector"
    return SCRIPT_DIR


MOBILE_EXPORTS_DIR = default_output_root() / "Mobile_Exports"
MOBILE_NO_BYPASS_STATEMENT = (
    "Owner-exported staging folder only; no live phone, cloud account, encrypted data, "
    "app-private data, passcode bypass, backup, developer mode, or security-control bypass was accessed."
)


@dataclass(frozen=True)
class Disk:
    """A safe-to-display external physical disk reported by diskutil."""

    identifier: str
    device_node: str
    size: int
    name: str
    protocol: str
    filesystem: str
    raw_info: dict[str, Any]

    @property
    def label(self) -> str:
        size_gib = self.size / (1024**3)
        return f"{self.identifier} — {self.name} ({size_gib:.2f} GiB, {self.protocol or 'external'})"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_folder_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip()).strip("._-")
    return cleaned or "Forensic_Triage_Output"


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def format_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    amount = float(value)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.2f} {unit}"
        amount /= 1024
    return f"{value} B"


def plist_command(command: list[str]) -> dict[str, Any] | None:
    """Return a macOS plist command result without executing through a shell."""
    try:
        result = subprocess.run(command, capture_output=True, check=False, timeout=20)
        if result.returncode != 0:
            return None
        loaded = plistlib.loads(result.stdout)
        return loaded if isinstance(loaded, dict) else None
    except (FileNotFoundError, OSError, plistlib.InvalidFileException, subprocess.TimeoutExpired):
        return None


def diskutil_info(target: str) -> dict[str, Any] | None:
    return plist_command(["/usr/sbin/diskutil", "info", "-plist", target])


def case_parent(metadata: dict[str, str]) -> Path:
    requested = metadata.get("destination_parent")
    parent = Path(requested).expanduser() if requested else default_output_root()
    if not parent.is_absolute() or not parent.is_dir() or parent.is_symlink():
        raise RuntimeError("Choose an existing, non-linked absolute destination folder.")
    return parent.resolve()


def output_disk_identifier(parent: Path | None = None) -> str | None:
    info = diskutil_info(str(parent or default_output_root()))
    if not info:
        return None
    return str(info.get("ParentWholeDisk") or info.get("DeviceIdentifier") or "") or None


def find_external_disks(destination_parent: Path | None = None) -> list[Disk]:
    """List only external, physical, whole disks and exclude the output disk."""
    listing = plist_command(["/usr/sbin/diskutil", "list", "-plist"])
    if not listing:
        return []
    excluded_disk = output_disk_identifier(destination_parent)
    identifiers = listing.get("AllDisks", [])
    disks: list[Disk] = []
    for identifier in identifiers if isinstance(identifiers, list) else []:
        if not isinstance(identifier, str) or re.search(r"s\d+$", identifier):
            continue
        info = diskutil_info(identifier)
        if not info:
            continue
        whole_disk = bool(info.get("WholeDisk"))
        internal = bool(info.get("Internal"))
        physical = str(info.get("VirtualOrPhysical", "")).lower() == "physical"
        device_id = str(info.get("DeviceIdentifier", identifier))
        if not whole_disk or internal or not physical or device_id == excluded_disk:
            continue
        device_node = str(info.get("DeviceNode", f"/dev/{device_id}"))
        disks.append(
            Disk(
                identifier=device_id,
                device_node=device_node,
                size=int(info.get("TotalSize") or info.get("Size") or 0),
                name=str(info.get("MediaName") or info.get("DiskUUID") or "Unnamed disk"),
                protocol=str(info.get("BusProtocol") or ""),
                filesystem=str(info.get("FilesystemType") or ""),
                raw_info=info,
            )
        )
    return sorted(disks, key=lambda disk: disk.identifier)


def mounted_volumes() -> list[Path]:
    root = Path("/Volumes")
    try:
        return sorted((entry for entry in root.iterdir() if entry.is_dir() and not entry.is_symlink()), key=lambda item: item.name.lower())
    except OSError:
        return []


def mobile_exports_root() -> Path:
    """Return the private, project-local staging root for owner-exported files."""
    try:
        MOBILE_EXPORTS_DIR.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if MOBILE_EXPORTS_DIR.exists():
            if MOBILE_EXPORTS_DIR.is_symlink() or not MOBILE_EXPORTS_DIR.is_dir():
                raise RuntimeError("Mobile_Exports must be a normal directory in the app data folder, not a link or file.")
        else:
            MOBILE_EXPORTS_DIR.mkdir(mode=0o700)
        os.chmod(MOBILE_EXPORTS_DIR, 0o700)
        return MOBILE_EXPORTS_DIR.resolve()
    except OSError as exc:
        raise RuntimeError(f"Cannot prepare the Mobile_Exports staging area: {exc}") from exc


def mobile_export_folders() -> list[Path]:
    """List only direct, non-symlinked export folders within the staging root."""
    root = mobile_exports_root()
    try:
        candidates = list(root.iterdir())
    except OSError as exc:
        raise RuntimeError(f"Cannot list Mobile_Exports: {exc}") from exc
    folders: list[Path] = []
    for candidate in candidates:
        try:
            if candidate.is_symlink() or not candidate.is_dir():
                continue
            if candidate.resolve().parent == root:
                folders.append(candidate)
        except OSError:
            continue
    return sorted(folders, key=lambda item: item.name.lower())


def is_mobile_export_folder(source: Path) -> bool:
    """Allow only a direct, normal child of the dedicated staging root."""
    try:
        root = mobile_exports_root()
        return (
            not source.is_symlink()
            and source.is_dir()
            and source.resolve().parent == root
        )
    except (OSError, RuntimeError):
        return False


def mobile_import_ready(authorized: bool, consented: bool, source: Path | None, typed_name: str) -> bool:
    """Keep mobile collection disabled until all authority and scope checks pass."""
    return bool(
        authorized
        and consented
        and source
        and is_mobile_export_folder(source)
        and typed_name.strip() == source.name
    )


def is_appledouble_sidecar(path: Path) -> bool:
    return path.name.startswith("._")


def classify_artifact(path: Path, selected: set[str]) -> str | None:
    # macOS writes AppleDouble sidecar files (for example, ._photo.jpeg) on
    # some removable-media formats. They are Finder metadata, not the primary
    # user document or image selected for this logical collection.
    if is_appledouble_sidecar(path):
        return None
    name = path.name.lower()
    if "Documents" in selected and path.suffix.lower() in DOCUMENT_EXTENSIONS:
        return "Documents"
    if "Images" in selected and path.suffix.lower() in IMAGE_EXTENSIONS:
        return "Images"
    if "Browser History Databases" in selected:
        if name in BROWSER_DATABASES:
            return "Browser_History"
        for database in BROWSER_DATABASES:
            if name in {f"{database}-wal", f"{database}-shm"}:
                return "Browser_History"
    return None


def classify_mobile_artifact(path: Path, selected: set[str]) -> str | None:
    """Classify only owner-exported, user-visible mobile-file types."""
    if is_appledouble_sidecar(path):
        return None
    suffix = path.suffix.lower()
    if "Documents" in selected and suffix in DOCUMENT_EXTENSIONS:
        return "Documents"
    if "Photos" in selected and suffix in IMAGE_EXTENSIONS:
        return "Photos"
    if "Videos" in selected and suffix in VIDEO_EXTENSIONS:
        return "Videos"
    return None


def artifact_paths(
    source: Path,
    selected: set[str],
    excluded: Path | None,
    log: Callable[[str], None],
    classifier: Callable[[Path, set[str]], str | None] = classify_artifact,
) -> Iterable[tuple[Path, str]]:
    """Yield regular source files only; never descend into symlinked directories."""
    excluded_resolved = excluded.resolve() if excluded else None
    for root, directories, filenames in os.walk(source, topdown=True, followlinks=False, onerror=lambda exc: log(f"SCAN ERROR: {exc}")):
        current = Path(root)
        kept_directories: list[str] = []
        for directory in directories:
            candidate = current / directory
            try:
                if candidate.is_symlink():
                    log(f"SKIP SYMLINK DIRECTORY: {candidate}")
                    continue
                if excluded_resolved and is_within(candidate, excluded_resolved):
                    log(f"SKIP OUTPUT DIRECTORY: {candidate}")
                    continue
            except OSError as exc:
                log(f"SCAN ERROR: {candidate}: {exc}")
                continue
            kept_directories.append(directory)
        directories[:] = kept_directories
        for filename in filenames:
            candidate = current / filename
            try:
                if candidate.is_symlink() or not candidate.is_file():
                    continue
            except OSError as exc:
                log(f"SCAN ERROR: {candidate}: {exc}")
                continue
            category = classifier(candidate, selected)
            if category:
                yield candidate, category


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(CHUNK_SIZE):
            digest.update(block)
    return digest.hexdigest()


def timestamp_fields(path: Path) -> dict[str, str]:
    stat_result = path.stat()
    fields = {
        "modified_utc": datetime.fromtimestamp(stat_result.st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "accessed_utc": datetime.fromtimestamp(stat_result.st_atime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "metadata_changed_utc": datetime.fromtimestamp(stat_result.st_ctime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if hasattr(stat_result, "st_birthtime"):
        fields["birth_utc"] = datetime.fromtimestamp(stat_result.st_birthtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        fields["birth_utc"] = "unavailable"
    return fields


class CaseWriter:
    """Writes a human-readable evidence manifest and operational log."""

    def __init__(self, root: Path, metadata: dict[str, str]):
        self.root = root
        self.manifest = root / "evidence_manifest.txt"
        self.log_file = root / "collection.log"
        root.mkdir(parents=True, exist_ok=False)
        os.chmod(root, 0o700)
        header = [
            "Mac-to-Autopsy Triage Collector — Evidence Manifest",
            f"Collection started (UTC): {utc_now()}",
            "This manifest records source metadata and hashes. Destination creation timestamps are not evidence timestamps.",
        ]
        header.extend(f"{key}: {value}" for key, value in metadata.items())
        self.manifest.write_text("\n".join(header) + "\n", encoding="utf-8")
        self.log_file.write_text(f"{utc_now()} | CASE CREATED | {root}\n", encoding="utf-8")
        os.chmod(self.manifest, 0o600)
        os.chmod(self.log_file, 0o600)

    def log(self, message: str) -> None:
        with self.log_file.open("a", encoding="utf-8") as handle:
            handle.write(f"{utc_now()} | {message}\n")

    def record(self, title: str, fields: dict[str, Any]) -> None:
        lines = [f"\n--- {title} ---"]
        lines.extend(f"{key}: {value}" for key, value in fields.items())
        with self.manifest.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")


def finalize_case(writer: CaseWriter, summary: dict[str, Any]) -> Path:
    """Write a final checksum inventory compatible with macOS ``shasum -c``."""
    writer.record("CASE FINALIZED", {"completed_utc": utc_now(), **summary})
    inventory = writer.root / "SHA256SUMS.txt"
    entries: list[str] = []
    for item in sorted(writer.root.rglob("*")):
        if item.is_file() and item != inventory:
            # Do not use the GNU ``*filename`` binary marker: macOS shasum
            # treats that star as part of the filename during ``-c`` checks.
            entries.append(f"{sha256_file(item)}  {item.relative_to(writer.root)}")
    inventory.write_text("\n".join(entries) + "\n", encoding="utf-8")
    os.chmod(inventory, 0o600)
    return inventory


def write_collection_report(
    root: Path,
    metadata: dict[str, str],
    *,
    collection_mode: str,
    source_description: str,
    selected_artifacts: Iterable[str],
    counts: dict[str, int],
    file_records: list[dict[str, str]],
    scope_note: str,
) -> Path:
    """Create a factual, examiner-facing PDF summary of one completed collection."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise RuntimeError(
            "PDF reporting needs ReportLab. Install it with: python3 -m pip install --user reportlab"
        ) from exc

    report_path = root / "Collection_Report.pdf"
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], alignment=TA_CENTER, fontName="Helvetica-Bold",
        fontSize=18, leading=22, textColor=colors.HexColor("#17365D"), spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle", parent=styles["Normal"], alignment=TA_CENTER, fontSize=9,
        leading=12, textColor=colors.HexColor("#4A5568"), spaceAfter=16,
    )
    heading_style = ParagraphStyle(
        "ReportHeading", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=11,
        leading=14, textColor=colors.HexColor("#17365D"), spaceBefore=10, spaceAfter=5,
    )
    body_style = ParagraphStyle("ReportBody", parent=styles["BodyText"], fontName="Helvetica", fontSize=9, leading=12)
    cell_style = ParagraphStyle("ReportCell", parent=body_style, fontSize=7.5, leading=9, wordWrap="CJK")
    header_style = ParagraphStyle("ReportHeader", parent=cell_style, fontName="Helvetica-Bold", textColor=colors.white)

    def safe_text(value: Any) -> str:
        # Standard PDF fonts cannot represent every possible filename. Replace
        # unsupported characters rather than failing the evidence collection.
        normalized = str(value).encode("latin-1", errors="replace").decode("latin-1")
        return escape(normalized).replace("\n", "<br/>")

    def paragraph(value: Any, style: ParagraphStyle = body_style) -> Paragraph:
        return Paragraph(safe_text(value), style)

    def page_footer(canvas: Any, document: Any) -> None:
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#CBD5E0"))
        canvas.line(document.leftMargin, 0.52 * inch, LETTER[0] - document.rightMargin, 0.52 * inch)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#4A5568"))
        canvas.drawString(document.leftMargin, 0.35 * inch, "Collection Report - retain with the evidence case")
        canvas.drawRightString(LETTER[0] - document.rightMargin, 0.35 * inch, f"Page {document.page}")
        canvas.restoreState()

    document = SimpleDocTemplate(
        str(report_path), pagesize=LETTER, rightMargin=0.62 * inch, leftMargin=0.62 * inch,
        topMargin=0.62 * inch, bottomMargin=0.72 * inch,
        title="Evidence Collection Report", author=APP_TITLE,
    )
    case_rows = [
        [paragraph("Case ID", cell_style), paragraph(metadata.get("case_id") or "Not provided", cell_style)],
        [paragraph("Collector / examiner", cell_style), paragraph(metadata.get("examiner") or "Not provided", cell_style)],
        [paragraph("Authority basis", cell_style), paragraph(metadata.get("authority_basis") or "Not provided", cell_style)],
        [paragraph("Collection type", cell_style), paragraph(collection_mode.replace("_", " ").title(), cell_style)],
        [paragraph("Report generated (UTC)", cell_style), paragraph(utc_now(), cell_style)],
    ]
    case_table = Table(case_rows, colWidths=[1.45 * inch, 5.65 * inch])
    case_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF0F7")),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#B8C7D9")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    outcome_rows = [
        [paragraph("Verified files copied", cell_style), paragraph(counts.get("copied", 0), cell_style)],
        [paragraph("Copy errors", cell_style), paragraph(counts.get("errors", 0), cell_style)],
        [paragraph("Selected categories", cell_style), paragraph(", ".join(sorted(selected_artifacts)) or "None", cell_style)],
        [paragraph("Source", cell_style), paragraph(source_description, cell_style)],
    ]
    outcome_table = Table(outcome_rows, colWidths=[1.65 * inch, 5.45 * inch])
    outcome_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EDF7ED")),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#B7D5B8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    story = [
        Paragraph("Evidence Collection Report", title_style),
        Paragraph("Digital Evidence Collector for Autopsy - factual collection summary", subtitle_style),
        Paragraph("Case information", heading_style), case_table,
        Paragraph("Collection outcome", heading_style), outcome_table,
        Paragraph("Scope and limitations", heading_style),
        paragraph(scope_note),
        paragraph("This report documents collection and integrity verification only. It does not interpret the files or draw investigative conclusions."),
        Paragraph("Integrity materials", heading_style),
        paragraph(
            "This case includes evidence_manifest.txt, collection.log, and SHA256SUMS.txt. "
            "Every successful copied file had matching source and destination SHA-256 values before it was recorded. "
            "From the case folder, verify the completed inventory with: shasum -a 256 -c SHA256SUMS.txt."
        ),
    ]
    if collection_mode in {"logical", "mobile_logical_import"}:
        story.extend([
            Paragraph("Autopsy import", heading_style),
            paragraph("In Autopsy, add the logical_evidence folder as a Logical Files data source. Retain this report and the integrity materials with the case."),
        ])
    if file_records:
        story.append(Paragraph("Verified file inventory", heading_style))
        file_rows = [[paragraph("Category", header_style), paragraph("Relative path", header_style), paragraph("SHA-256", header_style)]]
        for entry in file_records:
            file_rows.append([
                paragraph(entry["category"], cell_style),
                paragraph(entry["relative_path"], cell_style),
                paragraph(entry["sha256"], cell_style),
            ])
        file_table = Table(file_rows, colWidths=[1.05 * inch, 2.85 * inch, 3.2 * inch], repeatRows=1)
        file_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#B8C7D9")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(file_table)
    document.build(story, onFirstPage=page_footer, onLaterPages=page_footer)
    os.chmod(report_path, 0o600)
    return report_path


def revalidate_external_disk(selected: Disk, destination_parent: Path | None = None) -> Disk:
    """Prevent a stale UI choice from being used after drives change."""
    current = next((disk for disk in find_external_disks(destination_parent) if disk.identifier == selected.identifier), None)
    if not current:
        raise RuntimeError("The selected external disk is no longer present or is no longer eligible.")
    if (current.device_node != selected.device_node or current.size != selected.size
            or current.name != selected.name or current.protocol != selected.protocol):
        raise RuntimeError("The selected disk changed after the scan. Scan again and reconfirm the source disk.")
    return current


def create_case(destination_name: str, metadata: dict[str, str]) -> CaseWriter:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = case_parent(metadata) / f"{safe_folder_name(destination_name)}_{stamp}"
    root = base
    suffix = 1
    while root.exists():
        suffix += 1
        root = base.parent / f"{base.name}_{suffix}"
    return CaseWriter(root, metadata)


def collect_directory(
    source: Path,
    selected: set[str],
    destination_name: str,
    metadata: dict[str, str],
    report: Callable[[str], None],
    *,
    collection_mode: str,
    source_metadata: dict[str, str],
    classifier: Callable[[Path, set[str]], str | None],
    event_prefix: str,
    record_prefix: str,
) -> tuple[Path, dict[str, int]]:
    """Copy selected files from a validated directory and verify every copy."""
    writer = create_case(destination_name, metadata | {"collection_mode": collection_mode, **source_metadata})
    output = writer.root / "logical_evidence"
    output.mkdir()
    os.chmod(output, 0o700)
    counts = {"copied": 0, "skipped": 0, "errors": 0}
    file_records: list[dict[str, str]] = []
    report(f"Case folder created: {writer.root}")

    def event(message: str) -> None:
        if message.startswith("SCAN ERROR:"):
            counts["errors"] += 1
        writer.log(message)
        report(message)

    event(f"{event_prefix} START | source={source}")
    for source_file, category in artifact_paths(
        source,
        selected,
        writer.root if is_within(writer.root, source) else None,
        event,
        classifier,
    ):
        try:
            relative = source_file.relative_to(source)
            destination = output / category / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            source_times = timestamp_fields(source_file)
            source_size = source_file.stat().st_size
            source_hash = sha256_file(source_file)
            shutil.copy2(source_file, destination, follow_symlinks=False)
            destination_hash = sha256_file(destination)
            if source_hash != destination_hash:
                counts["errors"] += 1
                writer.record(f"{record_prefix} FILE — HASH MISMATCH", {
                    "timestamp_utc": utc_now(), "original_path": source_file, "destination_path": destination,
                    "source_sha256": source_hash, "destination_sha256": destination_hash, **source_times,
                })
                event(f"HASH MISMATCH: {source_file}")
                continue
            counts["copied"] += 1
            file_records.append({
                "category": category,
                "relative_path": str(relative),
                "sha256": source_hash,
            })
            writer.record(f"{record_prefix} FILE", {
                "timestamp_utc": utc_now(), "category": category, "original_path": source_file,
                "destination_path": destination, "sha256": source_hash, "size_bytes": source_size,
                "copy_verified": "yes", **source_times,
            })
            event(f"COPIED: {source_file} -> {destination}")
        except (OSError, shutil.Error) as exc:
            counts["errors"] += 1
            writer.record(f"{record_prefix} FILE — ERROR", {"timestamp_utc": utc_now(), "original_path": source_file, "error": repr(exc)})
            event(f"COPY ERROR: {source_file}: {exc}")
    writer.record(f"{record_prefix} SUMMARY", {"completed_utc": utc_now(), **counts})
    event(f"{event_prefix} COMPLETE | {counts}")
    scope_note = (
        "This is an owner-exported logical file set. It is not a physical phone extraction and cannot recover "
        "deleted, encrypted, cloud, message, call-log, browser, or app-private data."
        if collection_mode == "mobile_logical_import"
        else "This is an allocated-file logical collection from an already-mounted volume. It does not recover deleted data."
    )
    collection_report = write_collection_report(
        writer.root,
        metadata,
        collection_mode=collection_mode,
        source_description=str(source),
        selected_artifacts=selected,
        counts=counts,
        file_records=file_records,
        scope_note=scope_note,
    )
    event(f"COLLECTION REPORT WRITTEN: {collection_report}")
    inventory = finalize_case(writer, {"collection_mode": collection_mode, **counts})
    report(f"CHECKSUM INVENTORY WRITTEN: {inventory}")
    return writer.root, counts


def collect_logical(
    source: Path,
    selected: set[str],
    destination_name: str,
    metadata: dict[str, str],
    report: Callable[[str], None],
) -> tuple[Path, dict[str, int]]:
    if source.is_symlink() or not source.is_dir() or source.parent != Path("/Volumes"):
        raise RuntimeError("The selected source volume is no longer an eligible mounted volume under /Volumes.")
    destination = case_parent(metadata)
    source_info = diskutil_info(str(source))
    output_info = diskutil_info(str(destination))
    if source_info and output_info:
        source_disk = source_info.get("ParentWholeDisk") or source_info.get("DeviceIdentifier")
        output_disk = output_info.get("ParentWholeDisk") or output_info.get("DeviceIdentifier")
        if source_disk and source_disk == output_disk:
            raise RuntimeError("The case destination is on the source volume's disk. Choose a different destination.")
    return collect_directory(
        source,
        selected,
        destination_name,
        metadata,
        report,
        collection_mode="logical",
        source_metadata={"source_volume": str(source)},
        classifier=classify_artifact,
        event_prefix="LOGICAL COLLECTION",
        record_prefix="LOGICAL",
    )


def collect_mobile_logical(
    source: Path,
    selected: set[str],
    destination_name: str,
    metadata: dict[str, str],
    report: Callable[[str], None],
) -> tuple[Path, dict[str, int]]:
    """Collect an owner-exported mobile-file set without interacting with a phone."""
    if not is_mobile_export_folder(source):
        raise RuntimeError("Select a direct, non-symlinked export folder inside Mobile_Exports.")
    try:
        if not any(source.iterdir()):
            raise RuntimeError("The selected mobile export folder is empty.")
    except OSError as exc:
        raise RuntimeError(f"The selected mobile export folder cannot be read: {exc}") from exc
    if not selected:
        raise RuntimeError("Select at least one mobile artifact category.")
    return collect_directory(
        source,
        selected,
        destination_name,
        metadata,
        report,
        collection_mode="mobile_logical_import",
        source_metadata={
            "mobile_export_folder": str(source),
            "mobile_export_categories": ", ".join(sorted(selected)),
            "mobile_access_boundary": MOBILE_NO_BYPASS_STATEMENT,
        },
        classifier=classify_mobile_artifact,
        event_prefix="MOBILE LOGICAL IMPORT",
        record_prefix="MOBILE LOGICAL",
    )


def sudo_available() -> tuple[bool, str]:
    try:
        result = subprocess.run(["/usr/bin/sudo", "-n", "true"], capture_output=True, text=True, timeout=8)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    return result.returncode == 0, result.stderr.strip() or result.stdout.strip()


def is_fat_family(filesystem: str) -> bool:
    return filesystem.lower() in {"msdos", "fat", "fat32", "vfat"}


def ewf_tool(name: str) -> str | None:
    """Find a separately installed libewf utility in CLI or packaged-app PATHs."""
    found = shutil.which(name)
    if found:
        return found
    for directory in (Path("/opt/homebrew/bin"), Path("/usr/local/bin")):
        candidate = directory / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def validate_disk_destination(disk: Disk, parent: Path, image_format: str) -> None:
    """Fail closed when the output media cannot be distinguished from the source."""
    output_id = output_disk_identifier(parent)
    if not output_id:
        raise RuntimeError("Cannot identify the destination disk. Choose another folder and scan again.")
    if output_id == disk.identifier:
        raise RuntimeError("The destination is on the selected source disk. Choose a different disk.")
    free_space = shutil.disk_usage(parent).free
    # E01 compression varies with source data; reserve capacity for the full stream.
    if free_space < disk.size:
        raise RuntimeError(
            f"Insufficient destination space: {format_bytes(free_space)} available; "
            f"at least {format_bytes(disk.size)} required."
        )
    output_info = diskutil_info(str(parent)) or {}
    if image_format == "raw" and is_fat_family(str(output_info.get("FilesystemType") or "")) and disk.size > 4 * 1024**3:
        raise RuntimeError("A FAT-family destination cannot hold a raw image larger than 4 GiB.")
    if image_format == "e01" and not all(ewf_tool(name) for name in ("ewfacquirestream", "ewfverify")):
        raise RuntimeError("E01 requires libewf. Install it on this Mac with: brew install libewf")


def image_disk(
    disk: Disk,
    destination_name: str,
    metadata: dict[str, str],
    report: Callable[[str], None],
    progress: Callable[[float], None],
    image_format: str = "raw",
) -> tuple[Path, str]:
    """Acquire the selected physical disk to raw DD or E01 and verify output."""
    if image_format not in {"raw", "e01"}:
        raise RuntimeError("Select Raw DD or E01 before imaging.")
    parent = case_parent(metadata)
    disk = revalidate_external_disk(disk, parent)
    validate_disk_destination(disk, parent, image_format)
    if (not metadata.get("evidence_number", "").strip()
            or not metadata.get("source_serial_label", "").strip()
            or not metadata.get("write_blocker", "").strip()
            or metadata.get("write_blocker_confirmed") != "yes"):
        raise RuntimeError("Evidence ID, drive serial or asset tag, and confirmed write-blocker details are required.")
    authorized, detail = sudo_available()
    if not authorized:
        raise RuntimeError(
            "Disk access is not authorized in this Terminal session. Launch the Terminal helper, "
            "or run sudo -v before starting Streamlit from the same Terminal. " + detail
        )
    writer = create_case(destination_name, metadata | {
        "collection_mode": "physical_disk_image", "image_format": image_format,
        "source_disk": disk.identifier, "source_device_node": disk.device_node,
        "source_size_bytes": str(disk.size), "source_media_name": disk.name,
        "source_protocol": disk.protocol, "source_filesystem": disk.filesystem,
        "source_serial_reported": str(disk.raw_info.get("SerialNumber") or disk.raw_info.get("DeviceSerialNumber") or "unavailable"),
        "application_version": APP_VERSION,
    })
    image_dir = writer.root / "disk_images"
    image_dir.mkdir()
    os.chmod(image_dir, 0o700)

    def event(message: str) -> None:
        writer.log(message)
        report(message)

    raw_node = disk.device_node.replace("/dev/disk", "/dev/rdisk", 1)
    if image_format == "e01":
        return acquire_e01(disk, raw_node, writer, metadata, event, report, progress)
    partial = image_dir / f"{disk.identifier}_raw.dd.partial"
    final = image_dir / f"{disk.identifier}_raw.dd"
    source_digest = hashlib.sha256()
    copied = 0
    command = ["/usr/bin/sudo", "-n", "/bin/dd", f"if={raw_node}", "bs=4m"]
    event(f"DISK IMAGE START | source={raw_node} | expected_bytes={disk.size}")
    writer.record("DISK IMAGE — START", {"timestamp_utc": utc_now(), "command": "sudo -n dd if=<approved raw device> bs=4m", "partial_output": partial})
    try:
        with partial.open("xb") as image_handle:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert process.stdout is not None
            while block := process.stdout.read(CHUNK_SIZE):
                image_handle.write(block)
                source_digest.update(block)
                copied += len(block)
                progress(min(copied / disk.size, 1.0) if disk.size else 0.0)
                if copied % (512 * 1024 * 1024) < CHUNK_SIZE:
                    event(f"IMAGE PROGRESS: {format_bytes(copied)} / {format_bytes(disk.size)}")
            image_handle.flush()
            os.fsync(image_handle.fileno())
            stderr = process.stderr.read().decode("utf-8", errors="replace") if process.stderr else ""
            exit_code = process.wait()
    except BaseException as exc:
        writer.record("DISK IMAGE — FAILED", {"timestamp_utc": utc_now(), "bytes_written": copied, "partial_output": partial, "error": repr(exc)})
        event(f"DISK IMAGE FAILED; partial output retained: {partial}")
        raise
    if exit_code != 0 or copied != disk.size:
        reason = f"dd did not complete cleanly (exit={exit_code}, bytes={copied}, expected={disk.size}). {stderr.strip()}"
        writer.record("DISK IMAGE — FAILED", {"timestamp_utc": utc_now(), "bytes_written": copied, "expected_bytes": disk.size, "partial_output": partial, "error": reason})
        event(f"DISK IMAGE FAILED; partial output retained: {partial}")
        raise RuntimeError(reason)
    stream_hash = source_digest.hexdigest()
    event("Verifying completed image SHA-256...")
    output_hash = sha256_file(partial)
    if stream_hash != output_hash:
        reason = "Image verification failed: streamed and stored SHA-256 values differ."
        writer.record("DISK IMAGE — FAILED", {"timestamp_utc": utc_now(), "stream_sha256": stream_hash, "stored_sha256": output_hash, "partial_output": partial, "error": reason})
        event(f"{reason} Partial output retained: {partial}")
        raise RuntimeError(reason)
    partial.rename(final)
    progress(1.0)
    writer.record("DISK IMAGE — VERIFIED", {
        "completed_utc": utc_now(), "source_disk": disk.identifier, "source_device_node": raw_node,
        "destination_image": final, "size_bytes": copied,
        "acquisition_stream_sha256": stream_hash, "stored_image_sha256": output_hash,
        "verification_method": "SHA-256 of acquisition stream compared with independent read of stored DD file",
        "copy_verified": "yes",
    })
    event(f"DISK IMAGE VERIFIED: {final} | SHA-256: {stream_hash}")
    inventory = finalize_case(writer, {"collection_mode": "raw_disk_image", "image_sha256": output_hash, "image_size_bytes": copied})
    report(f"CHECKSUM INVENTORY WRITTEN: {inventory}")
    return writer.root, stream_hash


def acquire_e01(
    disk: Disk,
    raw_node: str,
    writer: CaseWriter,
    metadata: dict[str, str],
    event: Callable[[str], None],
    report: Callable[[str], None],
    progress: Callable[[float], None],
) -> tuple[Path, str]:
    """Stream readable sectors into libewf, then independently verify E01 segments."""
    acquire_tool = ewf_tool("ewfacquirestream")
    verify_tool = ewf_tool("ewfverify")
    if not acquire_tool or not verify_tool:
        raise RuntimeError("E01 requires the libewf acquisition and verification tools.")
    image_dir = writer.root / "disk_images"
    pending = image_dir / "incomplete"
    pending.mkdir(mode=0o700)
    target = pending / f"{disk.identifier}_image"
    acquire_log = writer.root / "ewfacquire.log"
    verify_log = writer.root / "ewfverify.log"
    tool_version = subprocess.run([acquire_tool, "-V"], capture_output=True, text=True, check=False, timeout=10)
    writer.record("E01 TOOL", {"path": acquire_tool, "version": (tool_version.stdout + tool_version.stderr).strip()})
    command = [
        acquire_tool, "-q", "-B", str(disk.size), "-d", "sha256", "-c", "fast",
        "-f", "encase6", "-C", metadata["case_id"], "-D", metadata.get("evidence_description", "Disk acquisition"),
        "-e", metadata["examiner"], "-E", metadata["evidence_number"],
        "-l", str(acquire_log), "-t", str(target),
    ]
    source_command = ["/usr/bin/sudo", "-n", "/bin/dd", f"if={raw_node}", "bs=4m"]
    writer.record("E01 ACQUISITION — START", {
        "timestamp_utc": utc_now(), "source_device": raw_node, "expected_bytes": disk.size,
        "tool": acquire_tool, "format": "encase6", "compression": "fast", "digest": "sha256",
        "incomplete_output": pending,
    })
    event(f"E01 ACQUISITION START | source={raw_node} | expected_bytes={disk.size}")
    source_digest = hashlib.sha256()
    copied = 0
    source: subprocess.Popen[bytes] | None = None
    sink: subprocess.Popen[bytes] | None = None
    stderr_file = writer.root / "ewfacquire_stderr.log"
    try:
        with stderr_file.open("wb") as stderr_handle:
            source = subprocess.Popen(source_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            sink = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=stderr_handle)
            assert source.stdout is not None and sink.stdin is not None
            while block := source.stdout.read(CHUNK_SIZE):
                sink.stdin.write(block)
                source_digest.update(block)
                copied += len(block)
                progress(min(copied / disk.size, 1.0) if disk.size else 0.0)
            sink.stdin.close()
            source_error = source.stderr.read().decode("utf-8", errors="replace") if source.stderr else ""
            source_exit = source.wait()
            sink_exit = sink.wait()
        if source_exit != 0 or sink_exit != 0 or copied != disk.size:
            raise RuntimeError(
                f"E01 acquisition incomplete (reader exit={source_exit}, E01 exit={sink_exit}, "
                f"bytes={copied}, expected={disk.size}). {source_error.strip()}"
            )
        first_segment = target.with_suffix(".E01")
        if not first_segment.is_file():
            raise RuntimeError("The E01 tool completed without producing its first segment.")
        event("Verifying E01 segments with ewfverify...")
        verified = subprocess.run(
            [verify_tool, "-q", "-d", "sha256", "-l", str(verify_log), str(first_segment)],
            capture_output=True, text=True, check=False,
        )
        if verified.returncode != 0:
            raise RuntimeError("E01 verification failed: " + (verified.stderr or verified.stdout).strip())
        verification_text = verified.stdout + "\n" + verified.stderr
        if verify_log.is_file():
            verification_text += "\n" + verify_log.read_text(encoding="utf-8", errors="replace")
        matches = re.findall(r"SHA256 hash calculated over data:\s*([0-9a-f]{64})", verification_text, re.IGNORECASE)
        if not matches or any(value.lower() != source_digest.hexdigest() for value in matches):
            raise RuntimeError("E01 verification did not confirm a SHA-256 matching the acquisition stream.")
        segments = sorted(pending.glob(f"{target.name}.E*"))
        if not segments:
            raise RuntimeError("No verified E01 segments were found.")
        for segment in segments:
            segment.rename(image_dir / segment.name)
        pending.rmdir()
        stream_hash = source_digest.hexdigest()
        writer.record("E01 ACQUISITION — VERIFIED", {
            "completed_utc": utc_now(), "source_device": raw_node, "bytes_read": copied,
            "acquisition_stream_sha256": stream_hash, "verified_image_data_sha256": matches[0].lower(),
            "verification_method": "libewf ewfverify SHA-256 compared with the acquisition-stream SHA-256",
            "first_segment": image_dir / first_segment.name, "segment_count": len(segments),
            "acquisition_log": acquire_log, "verification_log": verify_log,
        })
        event(f"E01 VERIFIED: {len(segments)} segment(s) | acquisition stream SHA-256: {stream_hash}")
        progress(1.0)
        inventory = finalize_case(writer, {"collection_mode": "e01_disk_image", "acquisition_stream_sha256": stream_hash, "image_size_bytes": copied})
        report(f"CHECKSUM INVENTORY WRITTEN: {inventory}")
        return writer.root, stream_hash
    except BaseException as exc:
        for process in (source, sink):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        writer.record("E01 ACQUISITION — FAILED", {
            "timestamp_utc": utc_now(), "bytes_read": copied, "expected_bytes": disk.size,
            "incomplete_output": pending, "error": repr(exc),
        })
        event(f"E01 ACQUISITION FAILED; incomplete files retained in {pending}: {exc}")
        raise


def ui_reporter(placeholder: Any) -> Callable[[str], None]:
    if "live_logs" not in st.session_state:
        st.session_state.live_logs = []

    def report(message: str) -> None:
        st.session_state.live_logs.append(f"{utc_now()} | {message}")
        st.session_state.live_logs = st.session_state.live_logs[-500:]
        placeholder.code("\n".join(st.session_state.live_logs), language="text")

    return report


def apply_visual_theme() -> None:
    """Apply a readable purple, retro-terminal visual treatment to the UI."""
    st.markdown(
        """
        <style>
        :root { --ink:#f5f0ff; --muted:#c9bddf; --panel:#20162e; --border:#4b326d; --purple:#a855f7; --bright:#d8b4fe; --mint:#72f1c4; }
        .stApp { background:radial-gradient(circle at 88% 3%,rgba(168,85,247,.24),transparent 27rem),radial-gradient(circle at 8% 20%,rgba(114,241,196,.10),transparent 24rem),#100b19; color:var(--ink); }
        [data-testid="stHeader"] { background:rgba(16,11,25,.76); }
        [data-testid="stSidebar"] { background:linear-gradient(180deg,#1c1229,#100b19); border-right:1px solid var(--border); }
        [data-testid="stSidebar"] * { color:var(--ink); }
        .stApp h1,.stApp h2,.stApp h3 { color:#fff8ff; letter-spacing:-.02em; }
        .stApp p,.stApp li,.stApp label,.stApp .stCaption { color:var(--muted); }
        div[data-baseweb="tab-list"] { gap:.35rem; border-bottom:1px solid var(--border); }
        button[data-baseweb="tab"] { color:var(--muted)!important; border-radius:.45rem .45rem 0 0; font-weight:650; }
        button[data-baseweb="tab"][aria-selected="true"] { color:var(--bright)!important; border-bottom:3px solid var(--purple)!important; background:rgba(168,85,247,.11); }
        .stButton > button { background:linear-gradient(135deg,#8b3de0,#6d28d9); border:1px solid #d8b4fe; color:white; box-shadow:3px 3px 0 #31124d; font-weight:700; }
        .stButton > button:hover { background:linear-gradient(135deg,#a855f7,#7c3aed); border-color:#f0d9ff; }
        div[data-testid="stTextInput"] input,div[data-baseweb="select"] > div { background:rgba(32,22,46,.92)!important; border-color:#72508d!important; color:var(--ink)!important; }
        .hero-panel { position:relative; overflow:hidden; padding:2.1rem 2.25rem; margin:.45rem 0 1.1rem; border:1px solid #8750b7; border-radius:1rem; background:linear-gradient(120deg,rgba(49,26,72,.98),rgba(25,16,39,.98)); box-shadow:8px 8px 0 rgba(79,34,113,.42); }
        .hero-panel::after { content:""; position:absolute; width:16rem; height:16rem; right:-5rem; top:-9rem; border:1px solid rgba(216,180,254,.36); border-radius:50%; box-shadow:0 0 0 1.5rem rgba(168,85,247,.07),0 0 0 3.1rem rgba(168,85,247,.04); }
        .eyebrow { color:var(--mint)!important; font:800 .78rem ui-monospace,SFMono-Regular,Menlo,monospace; letter-spacing:.13em; text-transform:uppercase; margin:0 0 .7rem; }
        .hero-panel h1 { margin:0; font-size:clamp(2rem,5vw,3.7rem); line-height:1.02; }
        .hero-panel h1 span { color:var(--bright); }
        .hero-copy { max-width:48rem; font-size:1.08rem; line-height:1.6; margin:1rem 0 0; color:#e6daef!important; }
        .status-line { display:inline-block; margin-top:1.15rem; padding:.42rem .7rem; color:#b9ffe6!important; border:1px solid rgba(114,241,196,.42); border-radius:99px; font:700 .78rem ui-monospace,SFMono-Regular,Menlo,monospace; }
        .workflow-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:.85rem; margin:.8rem 0 1.2rem; }
        .workflow-card { min-height:11rem; padding:1.1rem; border:1px solid var(--border); border-radius:.8rem; background:rgba(32,22,46,.86); }
        .workflow-number { display:inline-flex; align-items:center; justify-content:center; width:2rem; height:2rem; margin-bottom:.75rem; border:1px solid var(--bright); border-radius:.3rem; color:var(--bright); font:800 .9rem ui-monospace,SFMono-Regular,Menlo,monospace; }
        .workflow-card h3 { margin:0 0 .4rem; font-size:1rem; }
        .workflow-card p { margin:0; line-height:1.45; }
        .boundary-card { padding:1rem 1.15rem; border-left:4px solid var(--mint); border-radius:0 .6rem .6rem 0; background:rgba(114,241,196,.08); color:#dcfff2!important; }
        .retro-rule { height:1px; margin:1.7rem 0; border:0; background:linear-gradient(90deg,var(--purple),transparent); }
        @media (max-width:700px) { .hero-panel { padding:1.5rem; box-shadow:4px 4px 0 rgba(79,34,113,.42); } .workflow-grid { grid-template-columns:1fr; } }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_landing_page() -> None:
    mobile_exports_name = escape(MOBILE_EXPORTS_DIR.name)
    st.markdown(
        """<section class="hero-panel"><p class="eyebrow">Mac → Autopsy / Evidence acquisition console</p><h1>Collect with care.<br><span>Examine with confidence.</span></h1><p class="hero-copy">A focused classroom workflow for authorized logical collections and verified physical disk images—built to hand documented evidence to Autopsy.</p><span class="status-line">● AUTHORITY + INTEGRITY + DOCUMENTATION</span></section>""",
        unsafe_allow_html=True,
    )
    st.markdown("### Your workflow")
    st.markdown(
        """<div class="workflow-grid"><article class="workflow-card"><span class="workflow-number">01</span><h3>Document authority</h3><p>Enter the case number, examiner, and authority basis in the case controls before collection unlocks.</p></article><article class="workflow-card"><span class="workflow-number">02</span><h3>Acquire the right scope</h3><p>Collect selected logical files, owner-exported mobile files, or a physical image of an approved external disk.</p></article><article class="workflow-card"><span class="workflow-number">03</span><h3>Verify &amp; examine</h3><p>Keep the manifest, log, and SHA-256 inventory, then import the evidence into Autopsy.</p></article></div><div class="boundary-card"><strong>Authorized use only.</strong> Do not use this software on media you do not own or lack documented authority to examine.</div><hr class="retro-rule">""",
        unsafe_allow_html=True,
    )
    st.markdown(f"""
### Collection modes

- **USB / Drive File Collection** — copies selected accessible files from one already-mounted external volume. It does not recover deleted data.
- **Physical Disk Image** — acquires one approved external physical disk to raw `.dd`, or E01 when `libewf` is installed. A tested hardware write blocker is required.
- **Owner-Exported Mobile Files** — copies only documents, photos, and videos the owner places in `{mobile_exports_name}/[export-name]` in the app data folder.

It does **not** unlock phones, defeat encryption, bypass access controls, recover cloud data, create phone backups, use developer mode, access app-private data, or image this Mac's startup disk.

### Before collecting

1. Document authority, the case ID, and examiner identity.
2. Choose an existing case output location on a disk separate from the source. Disk images require at least the source disk's full capacity free.
3. For physical imaging, validate your write blocker with sacrificial media first and record its read-only status. A source may already have changed if connected without one.
4. Start the app from source with `python3 -m streamlit run mac_to_autopsy_triage.py`, or use the packaged macOS app.

For raw imaging, authorize the narrowly used system reader in the same Terminal first, then launch the app normally:

`sudo -v && python3 -m streamlit run mac_to_autopsy_triage.py`

The app never accepts or stores a password and never runs a source-writing command. For the packaged app, use the included Terminal imaging launcher to establish the same-session `sudo` authorization. E01 additionally requires `brew install libewf`.

### Physical disk acquisition checklist

1. Record the evidence item ID, source serial/asset tag, description, examiner, authority, write blocker make/model, and blocker serial if present.
2. Attach the approved physical source through a tested hardware write blocker. Select the whole external disk, confirm its displayed size and identifier, and choose raw DD or E01.
3. Confirm a separate destination disk with enough free space; type the source disk identifier and affirm the write-blocker status.
4. Acquire. A read error, short read, or failed verification leaves clearly marked incomplete output; do not treat it as a verified image.
5. Retain the case log, manifest, and checksum inventory. Raw DD compares the acquisition-stream SHA-256 with an independent read of the saved image. E01 is checked using `ewfverify` and records the source-stream SHA-256.

This workflow aligns with common forensic acquisition controls, but the program and a specific hardware setup still require validation before evidentiary use. Source media, enclosure, write blocker, and destination must be documented outside the app as needed for your lab's chain of custody.

### Owner-Exported Mobile Files

This feature simulates a complete collection of the **owner-approved exported file set**. It is not a physical phone image and cannot recover deleted, encrypted, cloud, message, call-log, browser, or app-private data.

1. Use only an owner-approved, unlocked test phone.
2. The owner manually exports selected documents, photos, and videos to `{mobile_exports_name}/[export-name]` in the app data folder shown on the mobile tab.
3. Do not connect this app directly to a phone or enable developer mode, device backup, account access, or security-bypass features.
4. Enter the case information, then open **Owner-Exported Mobile Files**.
5. Select the matching export folder and artifact categories.
6. Read and check the mobile-consent statement, then type the selected folder name to confirm the narrow collection scope.
7. Run the import and retain `evidence_manifest.txt`, `collection.log`, and `SHA256SUMS.txt`.
8. Verify the completed case in Terminal with `shasum -a 256 -c SHA256SUMS.txt`.

### Importing into Autopsy

1. Create or open an Autopsy case and choose **Add Data Source**.
2. For a USB / Drive File Collection or Owner-Exported Mobile Files collection, choose **Logical Files** and select the completed `logical_evidence` folder.
3. For a physical image, choose **Image File** and select the verified `.dd` or first `.E01` segment in `disk_images`.
4. Retain `evidence_manifest.txt` and `collection.log` as your integrity and chain-of-custody records. Use the manifest as the source of original timestamps for logical copies.
""")


def render_logical_tab(authorized: bool, destination_name: str, base_metadata: dict[str, str]) -> None:
    st.header("USB / Drive File Collection")
    st.caption("Copies selected, accessible files from a mounted external volume. It does not recover deleted data.")
    if st.button("Scan Connected USB / External Drives", key="scan_volumes"):
        st.session_state.volumes = [str(item) for item in mounted_volumes()]
    volumes = [Path(item) for item in st.session_state.get("volumes", []) if Path(item).is_dir()]
    if not volumes:
        st.info("Click “Scan for Connected Drives” to list mounted volumes in /Volumes.")
    source_text = st.selectbox("Source USB or external drive", [""] + [str(item) for item in volumes], format_func=lambda value: "Select a mounted drive" if not value else value, key="logical_source")
    choices = st.multiselect("File types to collect", ARTIFACT_OPTIONS, default=ARTIFACT_OPTIONS, key="logical_artifacts")
    console = st.empty()
    if st.button("Create Verified File Collection", type="primary", disabled=not authorized, key="logical_execute"):
        if not source_text or not choices:
            st.error("Select one source volume and at least one artifact category.")
            return
        st.session_state.live_logs = []
        reporter = ui_reporter(console)
        try:
            with st.spinner("Collecting and verifying selected artifacts..."):
                case_root, counts = collect_logical(Path(source_text), set(choices), destination_name, base_metadata, reporter)
            if counts["errors"]:
                st.warning(f"Collection finished with errors: {counts['copied']} copied, {counts['errors']} errors. Review collection.log before using this case.")
            else:
                st.success(f"Verified file collection complete: {counts['copied']} copied, 0 errors.")
            st.code(str(case_root), language="text")
        except Exception as exc:
            st.error(f"Logical collection stopped: {exc}")


def render_mobile_tab(authorized: bool, destination_name: str, base_metadata: dict[str, str]) -> None:
    st.header("Owner-Exported Mobile Files")
    st.warning("Owner-exported files only. This tab never connects to, unlocks, backs up, or controls a phone.")
    st.caption(
        "It collects approved Documents, Photos, and Videos from one direct subfolder of the private Mobile_Exports staging area. "
        "It is not a physical phone extraction."
    )
    try:
        staging_root = mobile_exports_root()
        exports = mobile_export_folders()
    except RuntimeError as exc:
        st.error(f"Mobile staging area is unavailable: {exc}")
        return

    st.write("Owner-export staging area:")
    st.code(str(staging_root), language="text")
    if not exports:
        st.info("Create a new export subfolder there, then have the owner place only approved files inside it. Refresh the app after the export is complete.")
    source_text = st.selectbox(
        "Owner-exported mobile folder",
        [""] + [str(item) for item in exports],
        format_func=lambda value: "Select one direct Mobile_Exports subfolder" if not value else Path(value).name,
        key="mobile_source",
    )
    source = Path(source_text) if source_text else None
    choices = st.multiselect(
        "File types to collect",
        MOBILE_ARTIFACT_OPTIONS,
        default=MOBILE_ARTIFACT_OPTIONS,
        key="mobile_artifacts",
    )
    consented = st.checkbox(
        "I confirm this is an owner-approved export from an unlocked test phone, the owner selected these files, and no bypass or protected data access is requested.",
        key="mobile_consent",
    )
    typed_name = st.text_input(
        f"Type {source.name} to confirm this export folder" if source else "Select an export folder before confirming it",
        key="mobile_typed_folder",
        disabled=source is None,
    )
    ready = mobile_import_ready(authorized, consented, source, typed_name)
    if not authorized:
        st.info("Complete the case controls and documented-authority acknowledgment to unlock mobile collection.")
    elif source and not consented:
        st.info("Read and confirm the mobile-consent statement to unlock mobile collection.")
    elif source and consented and typed_name.strip() != source.name:
        st.info("Type the selected export-folder name exactly to unlock mobile collection.")

    console = st.empty()
    if st.button("Create Mobile Evidence Collection", type="primary", disabled=not ready, key="mobile_execute"):
        if source is None or not choices:
            st.error("Select one export folder and at least one artifact category.")
            return
        st.session_state.live_logs = []
        reporter = ui_reporter(console)
        try:
            with st.spinner("Collecting and verifying owner-exported mobile files..."):
                case_root, counts = collect_mobile_logical(source, set(choices), destination_name, base_metadata, reporter)
            if counts["errors"]:
                st.warning(f"Mobile import finished with errors: {counts['copied']} copied, {counts['errors']} errors. Review collection.log before using this case.")
            else:
                st.success(f"Mobile evidence collection complete: {counts['copied']} copied, 0 errors.")
            st.code(str(case_root), language="text")
        except Exception as exc:
            st.error(f"Mobile logical import stopped: {exc}")


def render_image_tab(authorized: bool, destination_name: str, base_metadata: dict[str, str]) -> None:
    st.header("Physical Disk Image")
    st.warning("This mode reads an entire external physical disk. Connect the approved source through a tested hardware write blocker.")
    if st.button("Scan for Eligible External Disks", key="scan_disks"):
        try:
            st.session_state.disks = find_external_disks(case_parent(base_metadata))
        except RuntimeError as exc:
            st.error(str(exc))
            return
    disks: list[Disk] = st.session_state.get("disks", [])
    if not disks:
        st.info("Click “Scan for Eligible External Disks”. Internal disks and the disk holding the selected case destination are excluded.")
        return
    selected_id = st.selectbox("External physical source disk", [""] + [disk.identifier for disk in disks], format_func=lambda item: "Select an external disk" if not item else next(disk.label for disk in disks if disk.identifier == item), key="image_source")
    if not selected_id:
        return
    disk = next(item for item in disks if item.identifier == selected_id)
    image_format = st.selectbox("Image format", ["raw", "e01"], format_func=lambda value: "Raw DD (.dd)" if value == "raw" else "E01 (compressed forensic container)", key="image_format")
    if image_format == "e01" and not all(ewf_tool(name) for name in ("ewfacquirestream", "ewfverify")):
        st.info("E01 requires libewf on this Mac: brew install libewf")
    evidence_number = st.text_input("Evidence item number", key="evidence_number")
    source_serial = st.text_input("Drive serial number or asset tag", key="source_serial_label")
    description = st.text_input("Evidence description", key="evidence_description")
    blocker = st.text_input("Write blocker make and model", key="write_blocker")
    blocker_serial = st.text_input("Write blocker serial number (if labeled)", key="write_blocker_serial")
    blocker_confirmed = st.checkbox("I verified the source is connected through the hardware write blocker and recorded its read-only status.", key="write_blocker_confirmed")
    st.markdown(
        f"**Source:** `{disk.device_node}` · {disk.name} · {format_bytes(disk.size)} · {disk.protocol or 'external'}  \n"
        f"**Destination parent:** `{base_metadata['destination_parent']}`  \n"
        f"**Format:** {'Raw DD' if image_format == 'raw' else 'E01'}"
    )
    st.caption("The source will not be mounted, unmounted, formatted, repaired, or written by this app. Any read error stops the acquisition and leaves the incomplete output clearly marked.")
    typed_disk = st.text_input(f"Type {disk.identifier} to confirm the physical source disk", key="typed_disk")
    console = st.empty()
    ready = all((authorized, typed_disk == disk.identifier, evidence_number.strip(), source_serial.strip(), blocker.strip(), blocker_confirmed))
    if st.button("Create and Verify Disk Image", type="primary", disabled=not ready, key="image_execute"):
        st.session_state.live_logs = []
        reporter = ui_reporter(console)
        status = st.progress(0.0)
        acquisition_metadata = base_metadata | {
            "evidence_number": evidence_number.strip(),
            "source_serial_label": source_serial.strip(),
            "evidence_description": description.strip(),
            "write_blocker": blocker.strip(),
            "write_blocker_serial": blocker_serial.strip() or "not recorded",
            "write_blocker_confirmed": "yes",
        }
        try:
            with st.spinner("Imaging the approved external disk. Do not disconnect it."):
                case_root, image_hash = image_disk(disk, destination_name, acquisition_metadata, reporter, status.progress, image_format)
            st.success("Disk image completed and verified.")
            st.code(f"Case folder: {case_root}\nAcquisition stream SHA-256: {image_hash}", language="text")
        except Exception as exc:
            st.error(f"Disk imaging did not complete: {exc}")


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, page_icon="🔎", layout="wide")
    apply_visual_theme()
    st.title(APP_TITLE)
    st.caption("Authorized collection and integrity verification for files you will examine in Autopsy.")
    if getattr(sys, "frozen", False):
        default_output_root().mkdir(parents=True, mode=0o700, exist_ok=True)
    with st.sidebar:
        st.subheader("Case Information")
        case_id = st.text_input("Case Number")
        st.caption("Case folders use the case number followed by a UTC timestamp.")
        examiner = st.text_input("Collector / Examiner")
        authority = st.text_input("Authority to Collect (owner, written consent, warrant, institutional authorization)")
        destination_parent = st.text_input("Case output location (existing folder)", value=str(default_output_root()))
        authorized = st.checkbox("I have documented authority to examine this source and understand this tool's limits.")
        if not authorized:
            st.info("Collection controls unlock after documented-authority acknowledgment.")
        elif not (case_id.strip() and examiner.strip() and authority.strip()):
            authorized = False
            st.warning("Case ID, examiner name, and authority basis are required before collection.")
    case_id = case_id.strip()
    destination_name = case_id or "Forensic_Triage_Output"
    base_metadata = {"case_id": case_id, "examiner": examiner.strip(), "authority_basis": authority.strip(), "destination_parent": destination_parent.strip(), "application": APP_TITLE, "application_version": APP_VERSION, "python": sys.version.split()[0]}
    landing, logical, mobile, image = st.tabs(["Overview & Instructions", "USB / Drive Files", "Owner-Exported Mobile Files", "Physical Disk Image"])
    with landing:
        render_landing_page()
    with logical:
        render_logical_tab(authorized, destination_name, base_metadata)
    with mobile:
        render_mobile_tab(authorized, destination_name, base_metadata)
    with image:
        render_image_tab(authorized, destination_name, base_metadata)


if __name__ == "__main__":
    main()

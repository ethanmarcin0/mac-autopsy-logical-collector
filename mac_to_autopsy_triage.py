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
SCRIPT_DIR = Path(__file__).resolve().parent
CHUNK_SIZE = 8 * 1024 * 1024
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv"}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".heic", ".tif", ".tiff", ".gif"}
VIDEO_EXTENSIONS = {".mp4", ".mov", ".m4v", ".avi", ".mkv", ".webm"}
BROWSER_DATABASES = {"history.db", "history", "places.sqlite"}
ARTIFACT_OPTIONS = ["Documents", "Images", "Browser History Databases"]
MOBILE_ARTIFACT_OPTIONS = ["Documents", "Photos", "Videos"]
MOBILE_EXPORTS_DIR = SCRIPT_DIR / "Mobile_Exports"
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


def output_disk_identifier() -> str | None:
    info = diskutil_info(str(SCRIPT_DIR))
    if not info:
        return None
    return str(info.get("ParentWholeDisk") or info.get("DeviceIdentifier") or "") or None


def find_external_disks() -> list[Disk]:
    """List only external, physical, whole disks and exclude the output disk."""
    listing = plist_command(["/usr/sbin/diskutil", "list", "-plist"])
    if not listing:
        return []
    excluded_disk = output_disk_identifier()
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
        if MOBILE_EXPORTS_DIR.exists():
            if MOBILE_EXPORTS_DIR.is_symlink() or not MOBILE_EXPORTS_DIR.is_dir():
                raise RuntimeError("Mobile_Exports must be a normal directory beside this script, not a link or file.")
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


def revalidate_external_disk(selected: Disk) -> Disk:
    """Prevent a stale UI choice from being used after drives change."""
    current = next((disk for disk in find_external_disks() if disk.identifier == selected.identifier), None)
    if not current:
        raise RuntimeError("The selected external disk is no longer present or is no longer eligible.")
    if current.device_node != selected.device_node or current.size != selected.size:
        raise RuntimeError("The selected disk changed after the scan. Scan again and reconfirm the source disk.")
    return current


def create_case(destination_name: str, metadata: dict[str, str]) -> CaseWriter:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = SCRIPT_DIR / f"{safe_folder_name(destination_name)}_{stamp}"
    root = base
    suffix = 1
    while root.exists():
        suffix += 1
        root = SCRIPT_DIR / f"{base.name}_{suffix}"
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
    if not source.is_dir() or source.parent != Path("/Volumes"):
        raise RuntimeError("The selected source volume is no longer an eligible mounted volume under /Volumes.")
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


def image_disk(
    disk: Disk,
    destination_name: str,
    metadata: dict[str, str],
    report: Callable[[str], None],
    progress: Callable[[float], None],
) -> tuple[Path, str]:
    """Copy an approved raw source stream to a partial image and verify it."""
    disk = revalidate_external_disk(disk)
    writer = create_case(destination_name, metadata | {
        "collection_mode": "raw_disk_image", "source_disk": disk.identifier, "source_device_node": disk.device_node,
        "source_size_bytes": str(disk.size), "source_media_name": disk.name,
    })
    image_dir = writer.root / "disk_images"
    image_dir.mkdir()
    os.chmod(image_dir, 0o700)

    def event(message: str) -> None:
        writer.log(message)
        report(message)

    free_space = shutil.disk_usage(writer.root).free
    if free_space < disk.size:
        reason = f"Insufficient destination space: {format_bytes(free_space)} available; {format_bytes(disk.size)} required."
        writer.record("DISK IMAGE — PRECHECK FAILED", {"timestamp_utc": utc_now(), "reason": reason})
        event(reason)
        raise RuntimeError(reason)
    output_info = diskutil_info(str(writer.root)) or {}
    output_filesystem = str(output_info.get("FilesystemType") or "")
    if is_fat_family(output_filesystem) and disk.size > 4 * 1024**3:
        reason = "The destination filesystem is FAT-family and cannot safely store this image larger than 4 GiB."
        writer.record("DISK IMAGE — PRECHECK FAILED", {"timestamp_utc": utc_now(), "reason": reason})
        event(reason)
        raise RuntimeError(reason)
    authorized, detail = sudo_available()
    if not authorized:
        reason = "Noninteractive sudo authorization is unavailable. In the same terminal, run: sudo -v && python3 -m streamlit run mac_to_autopsy_triage.py"
        writer.record("DISK IMAGE — PRECHECK FAILED", {"timestamp_utc": utc_now(), "reason": reason, "sudo_detail": detail})
        event(reason)
        raise RuntimeError(reason)

    raw_node = disk.device_node.replace("/dev/disk", "/dev/rdisk", 1)
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
        "destination_image": final, "size_bytes": copied, "sha256": stream_hash, "copy_verified": "yes",
    })
    event(f"DISK IMAGE VERIFIED: {final} | SHA-256: {stream_hash}")
    inventory = finalize_case(writer, {"collection_mode": "raw_disk_image", "image_sha256": stream_hash, "image_size_bytes": copied})
    report(f"CHECKSUM INVENTORY WRITTEN: {inventory}")
    return writer.root, stream_hash


def ui_reporter(placeholder: Any) -> Callable[[str], None]:
    if "live_logs" not in st.session_state:
        st.session_state.live_logs = []

    def report(message: str) -> None:
        st.session_state.live_logs.append(f"{utc_now()} | {message}")
        st.session_state.live_logs = st.session_state.live_logs[-500:]
        placeholder.code("\n".join(st.session_state.live_logs), language="text")

    return report


def render_landing_page() -> None:
    st.header("Overview and Instructions")
    st.warning("Authorized use only. Do not use this software on media you do not own or lack documented authority to examine.")
    st.markdown(f"""
### What this tool does

**USB / Drive File Collection** copies selected user files (including photos) from one already-mounted external volume.  
**Raw Disk Image (advanced)** makes a sector-by-sector `.dd` image of one approved external physical disk for examination in Autopsy.
**Owner-Exported Mobile Files** copies only owner-exported documents, photos, and videos from the private `{MOBILE_EXPORTS_DIR.name}` staging folder.

It does **not** unlock phones, defeat encryption, bypass access controls, recover cloud data, create phone backups, use developer mode, access app-private data, or image this Mac's startup disk.

### Before collecting

1. Obtain and document legal/organizational authority, the case ID, and examiner identity.
2. For evidentiary media, attach the source through a hardware write blocker whenever possible. A mounted drive may already have been changed if it was attached without one.
3. Keep enough free space beside this script for the output. Disk images require at least the source disk's full capacity.
4. Install Streamlit once: `python3 -m pip install streamlit`.
5. Start the app: `python3 -m streamlit run mac_to_autopsy_triage.py`.

For raw imaging, authorize the narrowly used system reader in the same Terminal first, then launch the app normally:

`sudo -v && python3 -m streamlit run mac_to_autopsy_triage.py`

The app never accepts or stores a password and never runs a source-writing command.

### Owner-Exported Mobile Files

This feature simulates a complete collection of the **owner-approved exported file set**. It is not a physical phone image and cannot recover deleted, encrypted, cloud, message, call-log, browser, or app-private data.

1. Use only an owner-approved, unlocked test phone.
2. The owner manually exports selected documents, photos, and videos to `{MOBILE_EXPORTS_DIR.name}/<export-name>` beside this script.
3. Do not connect this app directly to a phone or enable developer mode, device backup, account access, or security-bypass features.
4. Enter the case information, then open **Owner-Exported Mobile Files**.
5. Select the matching export folder and artifact categories.
6. Read and check the mobile-consent statement, then type the selected folder name to confirm the narrow collection scope.
7. Run the import and retain `evidence_manifest.txt`, `collection.log`, and `SHA256SUMS.txt`.
8. Verify the completed case in Terminal with `shasum -a 256 -c SHA256SUMS.txt`.

### Importing into Autopsy

1. Create or open an Autopsy case and choose **Add Data Source**.
2. For a USB / Drive File Collection or Owner-Exported Mobile Files collection, choose **Logical Files** and select the completed `logical_evidence` folder.
3. For a full image, choose **Image File** and select the verified `.dd` file in `disk_images`.
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
            st.success(f"Verified file collection complete: {counts['copied']} copied, {counts['errors']} errors.")
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
            st.success(f"Mobile evidence collection complete: {counts['copied']} copied, {counts['errors']} errors.")
            st.code(str(case_root), language="text")
        except Exception as exc:
            st.error(f"Mobile logical import stopped: {exc}")


def render_image_tab(authorized: bool, destination_name: str, base_metadata: dict[str, str]) -> None:
    st.header("Raw Disk Image (Advanced)")
    st.error("This mode reads an entire external physical disk. Use only with documented authority and preferably a hardware write blocker.")
    if st.button("Scan for Eligible External Disks", key="scan_disks"):
        st.session_state.disks = find_external_disks()
    disks: list[Disk] = st.session_state.get("disks", [])
    if not disks:
        st.info("Click “Scan for Eligible External Disks”. Internal disks and the disk holding this app are excluded.")
        return
    selected_id = st.selectbox("External physical source disk", [""] + [disk.identifier for disk in disks], format_func=lambda item: "Select an external disk" if not item else next(disk.label for disk in disks if disk.identifier == item), key="image_source")
    if not selected_id:
        return
    disk = next(item for item in disks if item.identifier == selected_id)
    st.write(f"Selected source: `{disk.device_node}` — {format_bytes(disk.size)}")
    st.caption("The destination is a new timestamped case folder beside this script. The source will not be mounted, unmounted, formatted, repaired, or written by this app.")
    typed_disk = st.text_input(f"Type {disk.identifier} to confirm the physical source disk", key="typed_disk")
    console = st.empty()
    if st.button("Create Verified Disk Image", type="primary", disabled=not authorized or typed_disk != disk.identifier, key="image_execute"):
        st.session_state.live_logs = []
        reporter = ui_reporter(console)
        status = st.progress(0.0)
        try:
            with st.spinner("Imaging the approved external disk. Do not disconnect it."):
                case_root, image_hash = image_disk(disk, destination_name, base_metadata, reporter, status.progress)
            st.success("Disk image completed and SHA-256 verified.")
            st.code(f"Case folder: {case_root}\nSHA-256: {image_hash}", language="text")
        except Exception as exc:
            st.error(f"Disk imaging did not complete: {exc}")


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, page_icon="🔎", layout="wide")
    st.title(APP_TITLE)
    st.caption("Authorized collection and integrity verification for files you will examine in Autopsy.")
    with st.sidebar:
        st.subheader("Case Information")
        destination_name = st.text_input("Output Case Folder", value="Forensic_Triage_Output")
        case_id = st.text_input("Case Number")
        examiner = st.text_input("Collector / Examiner")
        authority = st.text_input("Authority to Collect (owner, written consent, warrant, institutional authorization)")
        authorized = st.checkbox("I have documented authority to examine this source and understand this tool's limits.")
        if not authorized:
            st.info("Collection controls unlock after documented-authority acknowledgment.")
        elif not (case_id.strip() and examiner.strip() and authority.strip()):
            authorized = False
            st.warning("Case ID, examiner name, and authority basis are required before collection.")
    base_metadata = {"case_id": case_id.strip(), "examiner": examiner.strip(), "authority_basis": authority.strip(), "application": APP_TITLE, "python": sys.version.split()[0]}
    landing, logical, mobile, image = st.tabs(["Overview & Instructions", "USB / Drive Files", "Owner-Exported Mobile Files", "Raw Disk Image (Advanced)"])
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

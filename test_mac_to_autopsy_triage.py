"""Focused regression tests for the mobile logical-import safety boundary."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import mac_to_autopsy_triage as app


class MobileLogicalImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.original_script_dir = app.SCRIPT_DIR
        self.original_exports_dir = app.MOBILE_EXPORTS_DIR
        app.SCRIPT_DIR = self.root / "workspace"
        app.SCRIPT_DIR.mkdir()
        app.MOBILE_EXPORTS_DIR = app.SCRIPT_DIR / "Mobile_Exports"
        self.exports_root = app.mobile_exports_root()

    def tearDown(self) -> None:
        app.SCRIPT_DIR = self.original_script_dir
        app.MOBILE_EXPORTS_DIR = self.original_exports_dir
        self.tempdir.cleanup()

    def make_export(self, name: str = "approved_phone_export") -> Path:
        export = self.exports_root / name
        export.mkdir()
        return export

    def test_mobile_export_boundary_and_confirmation(self) -> None:
        export = self.make_export()
        nested = export / "nested"
        nested.mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        (self.exports_root / "linked_export").symlink_to(export, target_is_directory=True)

        self.assertEqual(app.mobile_export_folders(), [export])
        self.assertTrue(app.is_mobile_export_folder(export))
        self.assertFalse(app.is_mobile_export_folder(self.exports_root))
        self.assertFalse(app.is_mobile_export_folder(nested))
        self.assertFalse(app.is_mobile_export_folder(outside))
        self.assertFalse(app.mobile_import_ready(True, True, export, "wrong-name"))
        self.assertFalse(app.mobile_import_ready(True, False, export, export.name))
        self.assertTrue(app.mobile_import_ready(True, True, export, export.name))

    def test_mobile_artifact_filtering_skips_sidecars_and_links(self) -> None:
        export = self.make_export()
        nested = export / "nested"
        nested.mkdir()
        (nested / "report.pdf").write_bytes(b"document")
        (nested / "photo.jpeg").write_bytes(b"photo")
        (nested / "clip.mov").write_bytes(b"video")
        (nested / "._photo.jpeg").write_bytes(b"appledouble")
        (nested / "ignore.bin").write_bytes(b"unsupported")
        (nested / "linked-photo.jpeg").symlink_to(nested / "photo.jpeg")

        found = list(app.artifact_paths(export, set(app.MOBILE_ARTIFACT_OPTIONS), None, lambda _: None, app.classify_mobile_artifact))
        self.assertEqual(
            {(path.name, category) for path, category in found},
            {("report.pdf", "Documents"), ("photo.jpeg", "Photos"), ("clip.mov", "Videos")},
        )

    def test_existing_logical_artifact_filtering_remains_available(self) -> None:
        source = self.root / "usb_source"
        source.mkdir()
        (source / "report.pdf").write_bytes(b"document")
        (source / "photo.jpeg").write_bytes(b"photo")
        (source / "History").write_bytes(b"browser database")
        (source / "._photo.jpeg").write_bytes(b"appledouble")

        found = list(app.artifact_paths(source, set(app.ARTIFACT_OPTIONS), None, lambda _: None))
        self.assertEqual(
            {(path.name, category) for path, category in found},
            {("report.pdf", "Documents"), ("photo.jpeg", "Images"), ("History", "Browser_History")},
        )

    def test_mobile_collection_writes_verified_autopsy_ready_evidence(self) -> None:
        export = self.make_export()
        nested = export / "nested"
        nested.mkdir()
        (nested / "report.pdf").write_bytes(b"document")
        (nested / "photo.jpeg").write_bytes(b"photo")
        (nested / "clip.mp4").write_bytes(b"video")
        (nested / "._photo.jpeg").write_bytes(b"appledouble")

        messages: list[str] = []
        case_root, counts = app.collect_mobile_logical(
            export,
            set(app.MOBILE_ARTIFACT_OPTIONS),
            "MOBILE-TEST",
            {"case_id": "TEST", "examiner": "Tester", "authority_basis": "owner"},
            messages.append,
        )

        self.assertEqual(counts, {"copied": 3, "skipped": 0, "errors": 0})
        self.assertTrue((case_root / "logical_evidence" / "Documents" / "nested" / "report.pdf").is_file())
        self.assertTrue((case_root / "logical_evidence" / "Photos" / "nested" / "photo.jpeg").is_file())
        self.assertTrue((case_root / "logical_evidence" / "Videos" / "nested" / "clip.mp4").is_file())
        self.assertFalse(any(path.name.startswith("._") for path in (case_root / "logical_evidence").rglob("*")))
        report = case_root / "Collection_Report.pdf"
        self.assertTrue(report.is_file())
        self.assertTrue(report.read_bytes().startswith(b"%PDF-"))
        manifest = (case_root / "evidence_manifest.txt").read_text(encoding="utf-8")
        self.assertIn("collection_mode: mobile_logical_import", manifest)
        self.assertIn(app.MOBILE_NO_BYPASS_STATEMENT, manifest)
        verification = subprocess.run(
            ["shasum", "-a", "256", "-c", "SHA256SUMS.txt"],
            cwd=case_root,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(verification.returncode, 0, verification.stdout + verification.stderr)
        self.assertIn("Collection_Report.pdf: OK", verification.stdout)

    def test_mobile_collection_rejects_empty_or_out_of_scope_sources(self) -> None:
        empty = self.make_export("empty")
        with self.assertRaisesRegex(RuntimeError, "empty"):
            app.collect_mobile_logical(empty, {"Photos"}, "MOBILE-TEST", {}, lambda _: None)

        outside = self.root / "outside"
        outside.mkdir()
        (outside / "photo.jpeg").write_bytes(b"photo")
        with self.assertRaisesRegex(RuntimeError, "Mobile_Exports"):
            app.collect_mobile_logical(outside, {"Photos"}, "MOBILE-TEST", {}, lambda _: None)

    def test_repeated_case_name_stays_in_selected_output_folder(self) -> None:
        output = self.root / "cases"
        output.mkdir()
        metadata = {"destination_parent": str(output)}
        first = app.create_case("CASE-1", metadata)
        second = app.create_case("CASE-1", metadata)
        self.assertEqual(first.root.parent, output.resolve())
        self.assertEqual(second.root.parent, output.resolve())
        self.assertNotEqual(first.root, second.root)

    def test_scan_failure_is_counted_not_reported_as_zero_errors(self) -> None:
        source = self.make_export()
        (source / "photo.jpeg").write_bytes(b"photo")

        def failed_scan(_source, _selected, _excluded, log, _classifier):
            log("SCAN ERROR: permission denied")
            return iter(())

        with patch.object(app, "artifact_paths", side_effect=failed_scan):
            case_root, counts = app.collect_mobile_logical(
                source, {"Photos"}, "CASE-2",
                {"case_id": "CASE-2", "examiner": "Tester", "authority_basis": "owner"},
                lambda _: None,
            )
        self.assertEqual(counts["errors"], 1)
        self.assertIn("SCAN ERROR", (case_root / "collection.log").read_text())


class PhysicalImagingSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.destination = Path(self.tempdir.name)
        self.disk = app.Disk("disk9", "/dev/disk9", 1024, "Test disk", "USB", "", {})

    def test_destination_must_be_identifiable_and_separate(self) -> None:
        with patch.object(app, "output_disk_identifier", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "Cannot identify"):
                app.validate_disk_destination(self.disk, self.destination, "raw")
        with patch.object(app, "output_disk_identifier", return_value="disk9"):
            with self.assertRaisesRegex(RuntimeError, "source disk"):
                app.validate_disk_destination(self.disk, self.destination, "raw")

    def test_e01_requires_both_acquisition_and_verification_tools(self) -> None:
        with patch.object(app, "output_disk_identifier", return_value="disk1"), \
                patch.object(app, "diskutil_info", return_value={}), \
                patch.object(app, "ewf_tool", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "libewf"):
                app.validate_disk_destination(self.disk, self.destination, "e01")

    def test_revalidation_rejects_changed_device_identity(self) -> None:
        changed = app.Disk("disk9", "/dev/disk9", 1024, "Different disk", "USB", "", {})
        with patch.object(app, "find_external_disks", return_value=[changed]):
            with self.assertRaisesRegex(RuntimeError, "changed"):
                app.revalidate_external_disk(self.disk, self.destination)


if __name__ == "__main__":
    unittest.main()

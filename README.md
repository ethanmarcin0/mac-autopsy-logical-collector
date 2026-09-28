# Digital Evidence Collector for Autopsy

An educational macOS application that prepares authorized logical file collections and physical disk images for review in [Autopsy](https://www.autopsy.com/). Logical collections verify each copied file with SHA-256 and include a PDF collection report. Physical imaging supports raw DD and optional E01, with acquisition and verification records.

> **Authorized use only.** Use this software only on data you own or have documented authority to collect. It is not a validated replacement for professional forensic-acquisition software or legal advice.

## What it does

- **USB / Drive File Collection:** copies selected documents, images, and browser-history database files from an already-mounted external volume.
- **Owner-Exported Mobile Files:** copies owner-selected documents, photos, and videos from a project-local staging folder. The application never connects to, unlocks, backs up, or controls a phone.
- **Physical Disk Image (advanced):** acquires an approved external physical disk to raw `.dd` or E01 (with separately installed `libewf`). It records source and write-blocker details and verifies the saved output.
- **Integrity documentation:** creates an evidence manifest, collection log, and SHA-256 inventory. Logical cases also include a PDF collection report.

## What it does not do

- It does not bypass a passcode, encryption, access controls, or device security.
- It does not perform a full physical phone extraction or recover deleted, encrypted, cloud, message, call-log, browser, or app-private phone data.
- It does not write to, repair, format, mount, or unmount the selected source through the application.
- It does not make investigative conclusions about collected files.
- It does not certify that a particular write blocker or host setup preserved the source. Validate your full workflow before evidentiary use.

## Requirements

- macOS (Apple Silicon for the current downloadable app)
- Python 3.10 or later
- Permission to collect the selected source
- A tested hardware write blocker for physical disk imaging
- Optional: `libewf` (`brew install libewf`) for E01 acquisition and verification

If you download GitHub's source ZIP, extract it before running the commands below. Windows can install the Python dependencies with `py -m pip install -r requirements.txt`, but collection and disk imaging in this version depend on macOS `diskutil` and `/Volumes`; Windows execution is not supported.

Install the application dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## Start the application

```bash
python3 -m streamlit run mac_to_autopsy_triage.py
```

Open the local address Streamlit displays in your browser.

For a downloadable macOS `.app`, see the [Releases page](https://github.com/ethanmarcin0/mac-autopsy-logical-collector/releases). Release ZIPs are unsigned and architecture-specific. They include a Terminal launcher for physical imaging, which establishes administrator authorization without passing a password to the app. To build the bundle yourself on macOS, run `zsh build_macos.sh`; the ZIP is written to `dist/`. The app binds only to `127.0.0.1`.

## Basic workflow

1. Obtain and document authority, case number, examiner name, and collection basis.
2. In the application, complete **Case Information** and acknowledge documented authority.
3. Choose the appropriate collection tab.
4. Select only the authorized source and file types.
5. Run collection and retain the generated case folder.
6. From the completed case folder, verify the inventory:

   ```bash
   shasum -a 256 -c SHA256SUMS.txt
   ```

7. Retain the manifest, log, and checksum inventory. Logical cases also include `Collection_Report.pdf`.

## Owner-exported mobile files

This workflow is deliberately limited to an owner-exported file set. It does **not** connect directly to a phone.

1. Use only an owner-approved, unlocked test phone.
2. The owner manually exports approved files to `Mobile_Exports/<export-name>/` in the app data folder shown on the mobile tab. In the packaged app this is `~/Digital Evidence Collector/Mobile_Exports/`.
3. Open **Owner-Exported Mobile Files** in the application.
4. Select the matching direct export folder and the desired categories.
5. Confirm the consent statement and type the export-folder name exactly.
6. Run the collection.

The output is an Autopsy-ready logical file set, not a phone image.

## Importing into Autopsy

For USB / Drive File Collection and Owner-Exported Mobile Files:

1. Create or open an Autopsy case.
2. Select **Add Data Source** > **Logical Files**.
3. Select only the completed case's `logical_evidence` folder.

Do not select the entire case folder. Keep `Collection_Report.pdf`, `evidence_manifest.txt`, `collection.log`, and `SHA256SUMS.txt` as collection documentation.

For a verified disk image, select **Image File** in Autopsy and choose the `.dd` or first `.E01` segment within `disk_images`.

## Physical disk imaging

This mode follows key acquisition controls also found in professional imaging workflows: explicit source selection, case/evidence/examiner details, a required write-blocker attestation, destination checks, an acquisition log, and verification of the saved image. The workflow is similar in purpose to FTK Imager, but this project is independent and has not undergone comparable validation.

1. Confirm authority and record the evidence item ID, source serial or asset tag, description, and write blocker details.
2. Test the write blocker with sacrificial media; connect the approved source through it. Do not image a source that was attached unblocked and writable unless your procedure accounts for that exposure.
3. Choose the whole external physical disk, not a volume. Confirm size and disk identifier, choose raw DD or E01, and select a separate destination with at least the full source capacity free.
4. For source-code use, start in the same Terminal with `sudo -v && python3 -m streamlit run mac_to_autopsy_triage.py`. For the packaged download, open the included `Launch Disk Imaging.command`.
5. After acquisition, inspect the manifest and logs. A failed read or verification leaves incomplete output marked as such; do not treat it as a complete, verified image. Raw DD compares the SHA-256 of the acquisition stream with an independent read of the saved image. E01 uses `ewfverify` and records the acquisition-stream SHA-256.
6. From the case folder, run `shasum -a 256 -c SHA256SUMS.txt`. For E01, the inventory covers every segment; retain all segments together.

## Evidence-safety notes

- A mounted drive may have been changed by macOS before collection. For preservation-quality physical evidence, use an appropriate hardware write blocker and document the acquisition process.
- A source-stream hash is not a separately re-read hash of the original disk. Verification checks the saved image; it does not prove the pre-attachment state of the source.
- Confirm the destination has sufficient storage before imaging a disk.
- Do not add real evidence, exports, disk images, case numbers, personally identifying data, API keys, or credentials to this repository.
- Review the generated report and the checksum inventory as part of your case workflow.

## Testing

Run the regression suite before making or publishing changes:

```bash
python3 -m unittest -v test_mac_to_autopsy_triage.py
```

The tests use harmless temporary data. They check the mobile-folder boundary, sidecar/symlink exclusions, confirmation logic, copy verification, PDF-report generation, and macOS-compatible SHA-256 inventory verification.

## Repository layout

```text
mac_to_autopsy_triage.py       Streamlit application
test_mac_to_autopsy_triage.py  Automated regression tests
requirements.txt               Python dependencies
mac_app_launcher.py             Local-only bundled application launcher
build_macos.sh                  macOS .app and ZIP build recipe
Launch Disk Imaging.command     Same-Terminal administrator-auth launcher
DOWNLOAD_README.md              Instructions included in the ZIP
LICENSE                        MIT license
SECURITY.md                    Responsible vulnerability-reporting guidance
CONTRIBUTING.md                Contribution and safe-demo guidance
```

## License

This project is available under the [MIT License](LICENSE).

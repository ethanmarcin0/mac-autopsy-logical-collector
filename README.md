# Digital Evidence Collector for Autopsy

An educational macOS application that prepares authorized file collections for review in [Autopsy](https://www.autopsy.com/). It copies selected, accessible files into a documented case folder, verifies copied files with SHA-256, and creates a concise PDF collection report.

> **Authorized use only.** Use this software only on data you own or have documented authority to collect. This is an educational, logical-collection tool - not a validated replacement for professional forensic-acquisition software or legal advice.

## What it does

- **USB / Drive File Collection:** copies selected documents, images, and browser-history database files from an already-mounted external volume.
- **Owner-Exported Mobile Files:** copies owner-selected documents, photos, and videos from a project-local staging folder. The application never connects to, unlocks, backs up, or controls a phone.
- **Raw Disk Image (advanced):** can create and verify a sector-by-sector `.dd` image of an approved external physical disk.
- **Integrity documentation:** creates an evidence manifest, collection log, SHA-256 inventory, and PDF collection report for each successful case.

## What it does not do

- It does not bypass a passcode, encryption, access controls, or device security.
- It does not perform a full physical phone extraction or recover deleted, encrypted, cloud, message, call-log, browser, or app-private phone data.
- It does not write to, repair, format, mount, or unmount the selected source through the application.
- It does not make investigative conclusions about collected files.

## Requirements

- macOS
- Python 3.10 or later
- Permission to collect the selected source
- Download zip file first. 

Install the application dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## Start the application

```bash
python3 -m streamlit run mac_to_autopsy_triage.py
```

Open the local address Streamlit displays in your browser.

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

7. Retain the manifest, log, checksum inventory, and `Collection_Report.pdf` with the case.

## Owner-exported mobile files

This workflow is deliberately limited to an owner-exported file set. It does **not** connect directly to a phone.

1. Use only an owner-approved, unlocked test phone.
2. The owner manually exports approved files to `Mobile_Exports/<export-name>/` beside the application.
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

For a verified raw disk image, select **Image File** in Autopsy and choose the `.dd` file within `disk_images`.

## Evidence-safety notes

- A mounted drive may have been changed by macOS before collection. For preservation-quality physical evidence, use an appropriate hardware write blocker and document the acquisition process.
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
LICENSE                        MIT license
SECURITY.md                    Responsible vulnerability-reporting guidance
CONTRIBUTING.md                Contribution and safe-demo guidance
```

## License

This project is available under the [MIT License](LICENSE).

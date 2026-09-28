#!/bin/zsh
# Build a macOS app and redistributable zip; run on the target CPU architecture.
set -e
project_dir="${0:A:h}"
cd "$project_dir"
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt 'pyinstaller>=6,<7'
.venv/bin/pyinstaller --noconfirm --clean --windowed --onedir \
  --name 'Digital Evidence Collector' \
  --collect-all streamlit \
  --add-data 'mac_to_autopsy_triage.py:.' \
  mac_app_launcher.py
chmod +x 'Launch Disk Imaging.command'
mkdir -p dist/download
cp -R 'dist/Digital Evidence Collector.app' 'dist/download/'
cp 'Launch Disk Imaging.command' 'dist/download/'
cp DOWNLOAD_README.md 'dist/download/README.md'
rm -f 'dist/Digital-Evidence-Collector-macOS.zip'
ditto -c -k --sequesterRsrc --keepParent 'dist/download' 'dist/Digital-Evidence-Collector-macOS.zip'
echo "Download ready: $project_dir/dist/Digital-Evidence-Collector-macOS.zip"

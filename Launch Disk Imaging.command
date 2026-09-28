#!/bin/zsh
# Launch the packaged app from this Terminal after a same-session sudo check.
set -e
package_dir="${0:A:h}"
app_binary="$package_dir/Digital Evidence Collector.app/Contents/MacOS/Digital Evidence Collector"
if [[ ! -x "$app_binary" ]]; then
  print -u2 "Digital Evidence Collector.app is missing from this download."
  exit 1
fi
echo "Confirm the approved source and tested write blocker before imaging."
echo "macOS may request your administrator password. The app does not receive it."
/usr/bin/sudo -v
exec "$app_binary"

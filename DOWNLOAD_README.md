# Digital Evidence Collector for Autopsy — macOS download

This unsigned macOS app runs a local browser interface at `127.0.0.1`. It is not affiliated with FTK Imager or Autopsy. The bundle is built for the Mac architecture shown in its release notes.

1. Extract the full ZIP. Keep the `.app` and `Launch Disk Imaging.command` together.
2. For logical file collection, open `Digital Evidence Collector.app`. If macOS Gatekeeper blocks an app you independently trust, use Finder’s **Open** contextual command and review the publisher warning. Do not disable Gatekeeper globally.
3. For physical disk imaging, connect an authorized source through a tested hardware write blocker, then open `Launch Disk Imaging.command`. It requests a macOS administrator authorization in Terminal before opening the app. The app does not collect or store the password.
4. Enter case information and choose an existing output folder on a different disk from the source. The default app-data folder is `~/Digital Evidence Collector`.
5. E01 acquisition requires `libewf` installed separately on the Mac (`brew install libewf`). Raw DD does not require it.
6. Review the app’s Overview tab and [project README](https://github.com/ethanmarcin0/mac-autopsy-logical-collector#readme) before collecting.

This is educational software, not a validated forensic imaging product. Test with sacrificial media and verify the resulting image in a separate tool before using it for evidence work.

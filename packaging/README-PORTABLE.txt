GreyNOC CryptoScan — portable build
===================================

This is a self-contained executable. It needs no Python install.

The command is `gs` (simple GreyNOC Scan syntax). Run from a terminal:

    gs --help
    gs code ./my-repo --mosca
    gs tls example.com:443 --report report.md
    gs scan ./my-repo --tls example.com:443 --cbom cbom.json --sarif out.sarif --mosca
    gs diff before.json after.json

On macOS/Linux the binary is named `gs`; on Windows it is `gs.exe`. You may need
to mark it executable (`chmod +x gs`) after extracting on Unix.

Exit code is 2 when findings at or above --fail-on (default: critical) are
present, so it gates CI. `gs diff` exits 2 on a posture regression.

AUTHORIZED TESTING ONLY. You are responsible for ensuring you have permission
to scan any target. Authorized testing only · reproducible · no fabrication.

GreyNOC · GN-TOOL-CRYPTOSCAN-001 · https://github.com/GreyNOC/Crypto-Scan

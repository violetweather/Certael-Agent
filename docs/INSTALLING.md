# Install a prebuilt Certael Agent release

The Agent is installed once per computer. Games do not copy it into their own
directory. The only required configuration is the game operator's public trust
store; it contains public Ed25519 verification keys and never a private key.

## Windows 11 x64

1. Extract the Windows release ZIP.
2. Obtain `trust-store.json` from the game operator over its authenticated
   distribution channel.
3. Open an elevated PowerShell in the extracted directory.
4. Run:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\install\install.ps1 -TrustStore C:\path\to\trust-store.json
   ```

The launcher is installed at `C:\Program Files\Certael\certael-agent.exe` and
the trust store at `C:\Program Files\Certael\config\trust-store.json`.

## macOS 15 or Ubuntu 24.04

1. Extract the matching release archive.
2. Obtain the public `trust-store.json` from the game operator.
3. Run:

   ```bash
   sudo ./install/install.sh --trust-store /path/to/trust-store.json
   ```

The launcher is `/usr/local/bin/certael-agent` and the public trust store is
`/usr/local/etc/certael/trust-store.json`.

## Launch a protected game

```bash
certael-agent launch \
  --game /absolute/path/to/game \
  --trust-store /usr/local/etc/certael/trust-store.json
```

Windows uses the equivalent installed paths. The Agent starts the game with a
private inherited channel. The game relays a server-signed policy and short-lived
launch grant through its Certael engine SDK. Offline and Agent-disabled game
modes may start the game directly.

The stable launcher is separate from versioned Agent binaries. It validates the
atomic activation record and hashes the selected Agent before every start. This
allows a verified update or rollback to take effect on the next launch without
overwriting a running executable. See [UPDATES.md](UPDATES.md).

Never install a trust store sent through an unauthenticated chat message, never
put a signing private key in it, and never mark a secret-looking private key as
a false positive. The installer validates its strict schema, Ed25519 public-key
material, validity windows, file type, and permissions before changing the
active Agent version.

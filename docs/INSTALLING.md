# Install a prebuilt Certael Agent release

The Agent is installed once per computer. Games do not copy it into their own
directory. The base install has no game-specific global trust store. Each game
is added through a signed registration binding its public verification keys,
TUF update root, executable path, channel, and publisher endpoints.

## Windows 11 x64

1. Extract the Windows release ZIP.
2. Open an elevated PowerShell in the extracted directory.
3. Run:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\install\install.ps1
   ```

The launcher is installed at `C:\Program Files\Certael\certael-agent.exe`.

## macOS 15 or Ubuntu 24.04

1. Extract the matching release archive.
2. Run:

   ```bash
   sudo ./install/install.sh
   ```

The launcher is `/usr/local/bin/certael-agent`.

## Register a game

The publisher distributes `registration.pb`, `publisher-trust-store.json`, and
`update-root.json` with the game. Register them with the installed game root:

```powershell
& 'C:\Program Files\Certael\certael-agent.exe' register-game `
  --registration C:\Game\Certael\registration.pb `
  --publisher-trust-store C:\Game\Certael\publisher-trust-store.json `
  --update-root C:\Game\Certael\update-root.json --game-root C:\Game
```

```bash
sudo certael-agent register-game \
  --registration /opt/game/certael/registration.pb \
  --publisher-trust-store /opt/game/certael/publisher-trust-store.json \
  --update-root /opt/game/certael/update-root.json --game-root /opt/game
```

The installer accepts the same four options to install and register in one
step. They are all-or-nothing. Registrations are isolated under
`C:\ProgramData\Certael\games` or `/usr/local/etc/certael/games` and contain
public material only. Never distribute a signing private key.

Before a registration or key expires, install the publisher's newly signed
replacement atomically with `update-game-registration` and the same four
arguments. The registration ID must remain the same. Interrupted replacement
is recovered on the next registration operation; incomplete trust bindings fail
closed.

Publishers can add a signed local icon and optional cinematic hero image with
`--branding-manifest` and `--branding-root`. The arguments must be supplied
together. See [the publisher launch splash guide](LAUNCH-SPLASH.md) for the
manifest fields, asset checks, registered-file hashing, repair, and offline-play
controls.

## Launch a protected game

```bash
certael-agent list-games
certael-agent launch-game --registration-id my-game-production
```

Windows uses the equivalent installed paths. The Agent starts the game with a
private inherited channel. The game relays a server-signed policy, short-lived
launch grant, and signed whole-build manifest through its engine SDK. Offline and Agent-disabled game
modes may start the game directly.

The stable launcher is separate from versioned Agent binaries. It validates the
atomic activation record and hashes the selected Agent before every start. This
allows a verified update or rollback to take effect on the next launch without
overwriting a running executable. See [UPDATES.md](UPDATES.md).

Never install registration material sent through an unauthenticated chat message, never
put a signing private key in it, and never mark a secret-looking private key as
a false positive. The installer validates its strict schema, Ed25519 public-key
material, validity windows, file type, and permissions before changing the
active Agent version.

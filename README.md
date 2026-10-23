# LanShare 📡

Phone → laptop file sharing over the browser. Run it on your Arch machine,
scan the QR from your phone, enter the 4-digit code, drop your files.

Pure C, raw POSIX sockets, no frameworks. ~800 lines.

## Build & run

```sh
make
./lanshare               # shares ~/Downloads on the LAN
./lanshare ~/Videos      # share any folder
./lanshare ~/Videos --tunnel   # public https URL → works on any network
```

## Phone side

1. Open the camera → scan the QR (or type the printed URL)
2. The pairing code is already in the QR — page opens ready to upload
3. Drop files (or tap) → progress bar → done

Works both on the same WiFi (LAN mode) and across networks (`--tunnel`
mode via an anonymous SSH reverse tunnel — URL rotates every session).

## Waybar button

`make install`, then add to `~/.config/waybar/config.jsonc`:

```jsonc
"custom/lanshare": {
  "exec": "~/.local/bin/lanshare-waybar status",
  "on-click": "~/.local/bin/lanshare-waybar toggle",
  "interval": 5,
  "return-type": "json"
}
```

Click to start (QR pops up) / click to stop.

## Notes

- Uploads land in the shared folder; duplicates get `-1`, `-2` suffixes
- Wrong code 5× → 30 s lockout
- Terminal QR needs `qrencode` (`pacman -S qrencode`)
- Design decisions + rejected alternatives: see `DESIGN.md`

#!/bin/sh
# waybar-lanshare.sh — status + toggle for the waybar "custom/lanshare" module.
#
# waybar config (add to ~/.config/waybar/config.jsonc):
#   "custom/lanshare": {
#     "exec": "~/.local/bin/lanshare-waybar status",
#     "on-click": "~/.local/bin/lanshare-waybar toggle",
#     "interval": 5,
#     "return-type": "json"
#   }
# install: make install  (puts binary + this script in ~/.local/bin)

PIDFILE=/tmp/lanshare.pid
DIR="${LANSHARE_DIR:-$HOME/Downloads}"

running() { [ -f "$PIDFILE" ] && kill -0 "$(head -1 "$PIDFILE")" 2>/dev/null; }

case "${1:-status}" in
  status)
    if running; then
      printf '{"text":"⏹","class":"on","tooltip":"lanshare ON — click to stop"}'
    else
      printf '{"text":"📡","class":"off","tooltip":"lanshare OFF — click to start"}'
    fi
    ;;
  toggle)
    if running; then
      kill "$(head -1 "$PIDFILE")" 2>/dev/null
      rm -f "$PIDFILE" /tmp/lanshare-qr.png
      notify-send -a lanshare "lanshare stopped" 2>/dev/null
    else
      rm -f "$PIDFILE"
      setsid -f "$HOME/.local/bin/lanshare" "$DIR" >/tmp/lanshare.log 2>&1
      # give it a moment to bind + render the QR, then show it as a popup
      for i in 1 2 3 4 5 6 7 8 9 10; do
        [ -f /tmp/lanshare-qr.png ] && break; sleep 0.4
      done
      if [ -f /tmp/lanshare-qr.png ]; then
        setsid -f imv -f /tmp/lanshare-qr.png >/dev/null 2>&1
      elif command -v notify-send >/dev/null 2>&1; then
        notify-send -a lanshare "lanshare" "URL in terminal log (/tmp/lanshare.log)" 2>/dev/null
      fi
    fi
    ;;
esac

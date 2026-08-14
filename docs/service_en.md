# Run sftd as a Linux systemd service

Validate the configuration first; repeated failed logins can trigger temporary
gateway lockouts.

```bash
sft check-config config.toml
```

Install both binaries and the configuration:

```bash
sudo install -Dm755 target/release/sftd /usr/local/bin/sftd
sudo install -Dm755 target/release/sft /usr/local/bin/sft
sudo install -Dm600 config.toml /etc/sangfordetunz/config.toml
```

Create `/etc/systemd/system/sftd.service`:

```ini
[Unit]
Description=sangfordetunz VPN daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sftd --config /etc/sangfordetunz/config.toml
Restart=on-failure
RestartSec=5s
RuntimeDirectory=sangfordetunz
# TUN mode needs these privileges. Remove both lines if every profile is an
# aTrust proxy-only connection.
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Enable it, then control connections with `sft`:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sftd.service
sudo journalctl -u sftd.service -f

sudo sft up zju        # bring a profile up (or set autostart = true)
sudo sft status        # show active connections
sudo sft down zju
```

Notes:

- The configuration contains credentials and should remain readable only by
  root.
- The default control socket is `/run/sangfordetunz.sock`; `sft` needs read/write
  access to it, so run it as root (or grant the socket to a group).
- Interactive CAPTCHA/SMS prompts cannot be answered by a background daemon. Set
  `totp_secret` for a TOTP gateway, or reuse a preconfigured session.

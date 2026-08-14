# Run as a Linux systemd service

First run the client interactively and confirm the gateway settings. Repeated failed logins can trigger temporary gateway lockouts.

Install the release binary and configuration:

```bash
sudo install -Dm755 target/release/zju-connect /usr/local/bin/zju-connect
sudo install -Dm600 config.toml /etc/zju-connect/config.toml
```

Create `/etc/systemd/system/zju-connect.service`:

```ini
[Unit]
Description=ZJU Connect VPN
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/zju-connect --config /etc/zju-connect/config.toml
Restart=on-failure
RestartSec=5s
# TUN mode needs these privileges. Remove both lines for aTrust proxy-only mode.
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now zju-connect.service
sudo journalctl -u zju-connect.service -f
```

The configuration contains credentials and should remain readable only by root. Interactive CAPTCHA/SMS prompts are unsuitable for a background unit; complete those once interactively or use a supported TOTP configuration before enabling the service.

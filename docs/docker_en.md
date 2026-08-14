# Run sangfordetunz in Docker

Copy and edit the example configuration, then use the included Compose file:

```bash
cp config.toml.example config.toml
docker compose up --build -d
docker compose logs -f sangfordetunz
```

The container runs the daemon (`sftd`), reading `/etc/sangfordetunz/config.toml`,
with `/dev/net/tun` plus `NET_ADMIN` for TUN-mode profiles. For aTrust
proxy-only profiles those two privileges may be removed from
`docker-compose.yml`.

Control connections with `sft` inside the container:

```bash
docker compose exec sangfordetunz sft up zju
docker compose exec sangfordetunz sft status
docker compose exec sangfordetunz sft down zju
```

Set a profile's `autostart = true` to connect automatically when the container
starts. Interactive CAPTCHA/SMS challenges cannot be answered in daemon mode;
use `totp_secret` or a preconfigured session instead.

Because the proxies default to `127.0.0.1`, set the profile's `socks_bind`/
`http_bind` to `0.0.0.0` (with credentials or `allow_open_proxy = true`) for the
published container ports to reach them.

Do not bake credentials into an image. Keep `config.toml` outside the image and
restrict its filesystem permissions.

# Run the Rust/Linux client in Docker

Copy and edit the example configuration, then use the included Compose file:

```bash
cp config.toml.example config.toml
docker compose up --build -d
docker compose logs -f zju-connect
```

The container reads `/etc/zju-connect/config.toml`, publishes the SOCKS5 and HTTP proxy ports, and has `/dev/net/tun` plus `NET_ADMIN` for TUN mode. For aTrust proxy-only mode those two privileges may be removed from `docker-compose.yml`.

For a one-off interactive CAPTCHA or SMS challenge:

```bash
docker compose run --rm -it zju-connect
```

Do not bake credentials into an image. Keep `config.toml` outside the image and restrict its filesystem permissions.

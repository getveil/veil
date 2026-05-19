# Using `docker` inside `veil run`

`veil run` enforces credential interception by setting `HTTP_PROXY` /
`HTTPS_PROXY` in the child's environment and trusting Veil's CA via
`SSL_CERT_FILE` and friends. CLI tools that respect those env vars
(`gh`, `curl`, `npm`, `pip`, ...) flow through Veil automatically.

`docker` is different. On Linux the daemon shares the host network
namespace and standard env-var configuration works. On **macOS** —
Docker Desktop, Colima, Lima, Rancher Desktop, and any other macOS
Docker runtime — the daemon runs inside a Linux VM whose network stack
does **not** inherit the calling shell's `HTTPS_PROXY`. The `docker`
CLI sends commands over a Unix socket to that VM and the VM makes the
actual HTTPS call to your registry.

Result: from inside `veil run`, `docker push` and `docker login` bypass
Veil. Placeholder credentials reach the wire unmodified and your
registry will typically reply with `malformed HTTP Authorization
header`. `veil log` records nothing because the traffic never touched
the proxy.

This is a known gap; kernel-level enforcement (post-MVP) closes it.
Until then, the workaround is to configure the Docker daemon itself.

## Fixing this on macOS Docker Desktop

There are two things to do, both targeting Docker Desktop's daemon:
point it at Veil's proxy, and have it trust Veil's CA.

### 1. Find Veil's proxy URL and CA path

In any veil-initialized project:

```sh
veil status
```

Note the `CA` line — that's the path to Veil's root certificate (on
macOS, typically `~/Library/Application Support/veil/ca/root.pem`).

For the proxy URL, start a `veil run` session in a separate terminal
and look at the startup banner. The line `veil proxy active · …` is
followed by the listener address; the proxy URL is `http://127.0.0.1:<port>`.
The port is chosen per session — if you frequently start and stop
sessions, see "Known limitation" below.

### 2. Trust Veil's CA in the macOS keychain

Docker Desktop builds its daemon trust bundle from the user-trusted
CAs in the Mac Keychain. Add Veil's root there:

```sh
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  "$(veil status 2>/dev/null | awk '/^  CA/{print $3}' | sed "s|^~|$HOME|")"
```

(Or pass the literal path printed by `veil status` if the `awk` form
mangles a non-default location.)

This requires `sudo` because it modifies the System keychain. If you
prefer not to use `sudo`, you can add it to the login keychain
instead (`~/Library/Keychains/login.keychain`), but System keychain is
recommended for Docker Desktop.

### 3. Set Docker Desktop's proxy

Open Docker Desktop → Settings → Resources → Proxies. Choose **Manual
proxy configuration** and set both HTTP and HTTPS to the Veil proxy
URL from step 1. Click **Apply & restart**.

### 4. Verify

From inside a `veil run` session (using the same proxy URL Docker
Desktop is configured for):

```sh
echo "$REGISTRY_TOKEN" | docker login -u <user> --password-stdin docker.io
```

It should succeed. Then:

```sh
veil log
```

You should see the login request recorded.

## Known limitation: per-session proxy port

`veil run` chooses a fresh listener port for every session. Docker
Desktop's proxy setting is Mac-wide and does not follow your Veil
session, so the port baked into Docker Desktop's settings drifts the
moment you start a new session on a different port.

Workarounds:

- **Update Docker Desktop's proxy URL each time** you start a session
  whose docker traffic you want mediated.
- **Run `docker` outside `veil run`** for one-off pushes. You lose the
  audit trail for that operation, which may be acceptable if no Veil-
  managed credential is involved.
- **Wait for kernel-level enforcement.** The post-MVP enforcement
  layer (see [ARCHITECTURE.md](ARCHITECTURE.md)) removes the
  cooperative-env-var assumption and makes this gap moot.

## Alternative: per-registry CA trust

If you only push to a small set of registries and do not want to touch
the keychain, you can place Veil's CA at
`~/.docker/certs.d/<registry>:<port>/ca.crt` for each registry:

```sh
mkdir -p ~/.docker/certs.d/docker.io
cp "$(veil status 2>/dev/null | awk '/^  CA/{print $3}' | sed "s|^~|$HOME|")" \
   ~/.docker/certs.d/docker.io/ca.crt
```

This still requires the Docker Desktop proxy setting from step 3 —
the cert path just tells Docker which custom CA to trust when it makes
the HTTPS connection that the proxy intercepts.

## Linux

On Linux, configure the Docker daemon to use Veil's proxy via a
systemd drop-in:

```sh
sudo mkdir -p /etc/systemd/system/docker.service.d
sudo tee /etc/systemd/system/docker.service.d/http-proxy.conf <<EOF
[Service]
Environment="HTTP_PROXY=http://127.0.0.1:<veil-port>"
Environment="HTTPS_PROXY=http://127.0.0.1:<veil-port>"
EOF
sudo systemctl daemon-reload
sudo systemctl restart docker
```

Then install Veil's CA into the system trust store on the host:

```sh
sudo cp "$(veil status 2>/dev/null | awk '/^  CA/{print $3}' | sed "s|^~|$HOME|")" \
        /usr/local/share/ca-certificates/veil.crt
sudo update-ca-certificates
sudo systemctl restart docker
```

The same per-session-port issue applies — for frequent use, either
pick a stable Veil port or wait for kernel-level enforcement.

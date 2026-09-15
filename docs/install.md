# Installation

EasyVault ships as a single binary and installs a background **service** that
starts on boot. Install it from the EasySYS package repository so upgrades come
through your package manager. Linux packages are published for **x86_64** and
**arm64**; your package manager picks the right one.

=== "Debian / Ubuntu"

    ```bash
    # Add the EasyVault repository (signed)
    curl -fsSL https://repo.easysys.io/easyvault/stable/debian/key.gpg \
      | sudo gpg --dearmor -o /usr/share/keyrings/easysys.gpg
    echo "deb [signed-by=/usr/share/keyrings/easysys.gpg] https://repo.easysys.io/easyvault/stable/debian ./" \
      | sudo tee /etc/apt/sources.list.d/easyvault.list

    sudo apt update
    sudo apt install easyvault
    systemctl status easyvault          # listens on :8200, starts sealed
    ```

=== "RHEL / Fedora"

    ```bash
    sudo tee /etc/yum.repos.d/easyvault.repo >/dev/null <<'EOF'
    [easyvault]
    name=EasyVault
    baseurl=https://repo.easysys.io/easyvault/stable/redhat
    enabled=1
    gpgcheck=1
    gpgkey=https://repo.easysys.io/easyvault/stable/redhat/key.gpg
    EOF

    sudo dnf install easyvault
    systemctl status easyvault
    ```

=== "openSUSE / SLES"

    ```bash
    sudo zypper addrepo -fg https://repo.easysys.io/easyvault/stable/redhat easyvault
    sudo zypper install easyvault
    systemctl status easyvault
    ```

=== "Windows"

    Download and run the installer (`easyvault-<version>-x86_64.exe`) from
    **[repo.easysys.io/easyvault/stable/windows](https://repo.easysys.io/easyvault/stable/windows)**.

    It registers the **EasyVault** Windows service (automatic start, restarted on
    failure) and keeps the database, TLS certificates, `config.toml` and logs under
    `%ProgramData%\EasyVault`, so they survive upgrades and uninstalls. The Start
    menu shortcut opens the dashboard at `http://localhost:8200`.

=== "Manual download"

    For air-gapped hosts, grab the `.deb` or `.rpm` for your architecture from the
    [releases page](https://github.com/easysysio/EasyVault/releases):

    ```bash
    sudo dpkg -i easyvault_*_amd64.deb     # or _arm64.deb
    sudo rpm  -i easyvault-*.x86_64.rpm    # or .aarch64.rpm
    systemctl status easyvault
    ```

    Upgrades then mean downloading the next package by hand — the repository is
    the easier path where the host has network access.

## What the package installs

| Path | Contents |
|---|---|
| `/usr/bin/easyvault` | The server binary |
| `/etc/easyvault/config.toml` | Configuration, seeded from `config.toml.example` on first install — see [Operations](operations.md#configuration) |
| `/var/lib/easyvault` | The database and TLS certificates |
| `/var/log/easyvault` | `easyvault.log` and `easyvault_error.log` |

The package creates a dedicated **`easyvault`** system user and enables and starts
the systemd unit. The service runs unprivileged, with only `CAP_IPC_LOCK` so the
master key can be locked into RAM, and a hardened unit (`ProtectSystem=strict`,
`NoNewPrivileges`).

## First run

Open `http://<host>:8200`. A fresh instance starts **sealed** and walks you
through three steps in the browser: **initialize** (save your unseal shares),
**unseal**, and **create the master account**.

Next: [Initialize & unseal](unseal.md).

## Building from source

```bash
git clone https://github.com/easysysio/EasyVault
cd EasyVault
cp config.toml.example config.toml      # optional — sensible defaults otherwise
cargo run --release                     # listens on 0.0.0.0:8200, starts sealed
```

Run from source, EasyVault keeps its data under `$EASYVAULT_HOME` (default
`~/.easyvault`); set `EASYVAULT_CONFIG` to use a config file somewhere else.

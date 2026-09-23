# Wormhole

[![PyPI Version](https://img.shields.io/pypi/v/wormhole-proxy.svg)](https://pypi.org/project/wormhole-proxy/)
[![Quay.io Build Status](https://quay.io/repository/cwt/wormhole/status "Quay.io Build Status")](https://quay.io/repository/cwt/wormhole)

> 📖 **Complete Documentation**: See the [Wormhole OKF Documentation Portal](docs/index.md) for user guides, system architecture, security specifications, and development logs.

**Wormhole** is a forward proxy without caching. You may use it for:

  - Modifying requests to look like they are originated from the IP
    address that *Wormhole* is running on.
  - Adding an authentication layer to the internet users in your
    organization.
  - Logging internet activities to your syslog server.
  - Blocking ads and other unwanted content.

-----

## Features

  - **Secure Digest Authentication:** Wormhole supports HTTP Digest Authentication with the modern **SHA-256** algorithm. Passwords are never stored in plain text, providing a significant security improvement over Basic Authentication.
  - **Ad-blocking:** Wormhole can block domains based on a comprehensive list of ad-serving and tracking domains. You can create your own ad-block database or use the provided script to download and compile one from popular sources.
  - **Allowlist:** You can specify a list of domains that should never be blocked, ensuring that important services are always accessible.
  - **Blocklist:** You can specify a list of domains to always block (inverted allowlist), providing an alternative approach to domain filtering.
  - **Domain Filtering Priority:** When checking if a domain should be blocked, Wormhole follows this priority order: (1) Exact match in custom blocklist (highest priority - domains are blocked immediately), (2) Exact match in ad blocklist, (3) Exact match in allowlist, (4) Parent domain in custom blocklist, (5) Parent domain in ad blocklist, (6) Parent domain in allowlist (lowest priority). This allows fine-grained control over domain filtering where custom blocklists take precedence.
  - **HTTP/1.1 Upgrade:** Automatically attempts to upgrade HTTP/1.0 requests to HTTP/1.1 to leverage modern web features and improve performance.
  - **IPv6 Prioritization:** Prefers IPv6 connections when available for faster and more modern networking.
  - **Automatic IPv6 Detection:** Automatically detects when IPv6 becomes available and can restart the server to enable dual-stack support.
  - **Security:** Includes safeguards to prevent proxying to private and reserved IP addresses, mitigating the risk of SSRF (Server-Side Request Forgery) attacks.
  - **High Performance:** Built with `asyncio` and can leverage `uvloop` or `winloop` for even better performance. The number of concurrent connections is dynamically adjusted based on system limits.
  - **Tor Support (optional):** Routes all outbound traffic through a private, locally spawned **tor** daemon (never an unknown listener on `9050`/`9150`), with a bridge bootstrap ladder (obfs4, snowflake, webtunnel) for censored networks.

-----

## Dependency

  - Python \>= 3.11
  - aiodns
  - aiohttp
  - aiosqlite
  - loguru
  - pywin32 (required for Windows)
  - [uvloop](https://github.com/MagicStack/uvloop) (optional for Linux and macOS)
  - [winloop](https://github.com/Vizonex/Winloop) (optional for Windows)
  - [python-socks](https://github.com/romis2012/python-socks) and [stem](https://stem.torproject.org/) (optional, for `--tor`)
  - A system **tor** binary and pluggable transports (optional, for `--tor`)

-----

## How to install

### Stable Version

Please install the **stable version** using `pip` command:

```shell
$ pip install wormhole-proxy
```

### Development Snapshot

You can install the **development snapshot** from the **main** branch on GitHub using the following command:

```shell
$ pip install git+https://github.com/cwt/wormhole.git@main
```

Or install from your local clone:

```shell
$ git clone https://github.com/cwt/wormhole.git
$ cd wormhole/
$ pip install -e .
```

You can also install the latest snapshot from the main branch using the following
command:

```shell
$ pip install https://github.com/cwt/wormhole/archive/refs/heads/main.tar.gz
```

-----

## How to use

1.  Run **wormhole** command

    ```shell
    $ wormhole
    ```

2.  Set browser's proxy setting to

    ```shell
    host: 127.0.0.1
    port: 8800
    ```

### Authentication Setup

Wormhole includes built-in tools to securely manage users. These commands will prompt you to enter and confirm passwords interactively.

  * **To create an authentication file and add a new user:**

    ```shell
    $ wormhole --auth-add wormhole.passwd <username>
    ```

  * **To change an existing user's password:**

    ```shell
    $ wormhole --auth-mod wormhole.passwd <username>
    ```

  * **To delete a user:**

    ```shell
    $ wormhole --auth-del wormhole.passwd <username>
    ```

  * **To run the proxy with authentication enabled:**

    ```shell
    $ wormhole --auth wormhole.passwd
    ```

### Ad-Blocker Usage

1.  **Update the ad-block database:**

    ```shell
    $ wormhole --update-ad-block-db ads.sqlite3
    ```

2.  **Run Wormhole with the ad-blocker enabled:**

    ```shell
    $ wormhole --ad-block-db ads.sqlite3
    ```

    **Note:** If you used `--allowlist` and `--blocklist` during the `--update-ad-block-db` step, you still need to specify these options when running the server to apply them at runtime. The `--update-ad-block-db` step incorporates the allowlist/blocklist into the database, while server runtime options are applied separately for live filtering with the documented priority order.

### Tor Support (optional)

Wormhole can route all outbound traffic through a private, locally spawned **tor** daemon:

```shell
$ pip install 'wormhole-proxy[tor]'   # once, for python-socks and stem
$ wormhole --tor
```

The **tor** daemon itself must be installed with your system package manager. On
censored networks, Wormhole tries a direct connection first, then **obfs4** and
**webtunnel** when their transport binaries are available, and **snowflake**
only when `--tor-snowflake` is given (snowflake is slower to bootstrap).

**Fedora 44** (installs the `snowflake` and `webtunnel` transports):

```shell
$ sudo dnf copr enable vgaetera/extras
$ sudo dnf install tor snowflake webtunnel
```

Then run with the transports enabled:

```shell
$ wormhole --tor --tor-snowflake
```

The first visit to an **onion service** can take a couple of minutes while Tor
fetches its descriptor; subsequent visits are fast.

Use `--tor-bridge "obfs4 <address> <fingerprint> <params>"` (repeatable) or
`--tor-bridge-file PATH` to supply your own bridges from
[BridgeDB](https://bridges.torproject.org/), and `--tor-binary PATH` if the
daemon is not in `PATH`. If every attempt fails, Wormhole reports whether Tor
appears blocked or the network is offline: exit status `2` means tor or the
optional dependencies are missing, and `3` means all bootstrap attempts failed.

-----

## Command help

```shell
$ wormhole --help
```

The output will be similar to this:

```
usage: wormhole [-h] [-H HOST] [-p PORT] [--allow-private] [--auto-ipv6]
                [-S SYSLOG_HOST] [-P SYSLOG_PORT] [-l] [-v] [--auth AUTH_FILE]
                [--auth-add <AUTH_FILE> <USERNAME>]
                [--auth-mod <AUTH_FILE> <USERNAME>]
                [--auth-del <AUTH_FILE> <USERNAME>]
                [--ad-block-db AD_BLOCK_DB] [--update-ad-block-db DB_PATH]
                [--allowlist ALLOWLIST] [--blocklist BLOCKLIST] [--tor]
                [--tor-binary PATH] [--tor-bridge BRIDGE_LINE]
                [--tor-bridge-file PATH] [--tor-timeout SECONDS]
                [--tor-data-dir PATH] [--tor-pt-dir PATH] [--tor-no-bridges]
                [--tor-snowflake] [--tor-isolate-dest]

Wormhole (3.6.0): Asynchronous I/O HTTP/S Proxy

options:
  -h, --help            show this help message and exit
  -H, --host HOST       Host address to bind [default: 0.0.0.0]
  -p, --port PORT       Port to listen on [default: 8800]
  --allow-private       Allow proxying to private and reserved IP addresses
                        (disabled by default)
  --auto-ipv6           Automatically detect IPv6 availability and restart
                        server when IPv6 becomes available
  -S, --syslog-host SYSLOG_HOST
                        Syslog host or path (e.g., /dev/log)
  -P, --syslog-port SYSLOG_PORT
                        Syslog port [default: 514]
  -l, --license         Print license information and exit
  -v, --verbose         Increase verbosity (-v, -vv)

Authentication Options:
  --auth AUTH_FILE      Enable Digest authentication using the specified file.
  --auth-add <AUTH_FILE> <USERNAME>
                        Add a user to the authentication file and exit.
  --auth-mod <AUTH_FILE> <USERNAME>
                        Modify a user's password in the authentication file
                        and exit.
  --auth-del <AUTH_FILE> <USERNAME>
                        Delete a user from the authentication file and exit.

Ad-Blocker Options:
  --ad-block-db AD_BLOCK_DB
                        Path to the SQLite database file containing domains to
                        block.
  --update-ad-block-db DB_PATH
                        Fetch public ad-block lists and compile them into a
                        database file, then exit.
  --allowlist ALLOWLIST
                        Path to a file of domains to extend the default
                        allowlist.
  --blocklist BLOCKLIST
                        Path to a file of domains to block (inverted
                        allowlist).

Tor Options:
  --tor                 Route all outbound traffic through a private local tor
                        daemon.
  --tor-binary PATH     Path to the tor binary [default: search PATH].
  --tor-bridge BRIDGE_LINE
                        Bridge line to use (repeatable, forms a pool); implies
                        --tor.
  --tor-bridge-file PATH
                        File with one bridge line per line; implies --tor.
  --tor-timeout SECONDS
                        Bootstrap timeout per attempt [default: 90].
  --tor-data-dir PATH   Directory for persistent Tor state [default: platform
                        data dir].
  --tor-pt-dir PATH     Directory containing pluggable transport binaries.
  --tor-no-bridges      Only try a direct Tor connection (skip the bridge
                        ladder).
  --tor-snowflake       Enable the snowflake bridge rung (slow to bootstrap).
  --tor-isolate-dest    Isolate streams per destination address.
```

-----

## **Docker Image Usage**

Official images are available at [quay.io/cwt/wormhole](https://quay.io/repository/cwt/wormhole).

### **1. Pull the image**

Pull the desired version tag from Quay.io.

```shell
# Replace <tag> with a specific version, e.g., v3.6.0
podman pull quay.io/cwt/wormhole:<tag>
```

### **2. Run without special configuration**

To run Wormhole on the default port 8800 without authentication or ad-blocking:

```shell
podman run --rm -it -p 8800:8800 quay.io/cwt/wormhole:<tag>
```

### **3. Running with Ad-Blocker**

**Step A: Create the ad-block database on your host**

First, you need to have a local config path to save the generated database file.

```shell
mkdir -p /path/to/config  # change this to your desired path
```

Then, run the following command to create the ad-block database file:

```shell
podman run --rm -it -v /path/to/config:/config quay.io/cwt/wormhole:<tag> wormhole --update-ad-block-db /config/ads.sqlite3
```

This will create a file named ads.sqlite3 in `/path/to/config/` on your host.

**Step B: Run the container with the database mounted**

Now, run the container, mounting the ads.sqlite3 file into the container's `/config` directory.

```shell
# Using :ro mounts the database as read-only for better security.
podman run --rm -it -p 8800:8800 \
  -v /path/to/config/ads.sqlite3:/config/ads.sqlite3:ro \
  quay.io/cwt/wormhole:<tag> \
  wormhole --ad-block-db /config/ads.sqlite3
```

### **4. Running with Authentication**

**Step A: Create an authentication file**

First, you need to have a local config path to save the generated authentication file.

```shell
mkdir -p /path/to/config  # change this to your desired path
```

Run a temporary container to create the authentication file. You will be prompted to enter a password for the new user.

```shell
# Replace <username> with your desired username
podman run --rm -it -v /path/to/config:/config quay.io/cwt/wormhole:<tag> \
  wormhole --auth-add /config/wormhole.passwd <username>
```

**Step B: Run the container with the auth file mounted**

Mount the authentication file into the `/config` directory.

```shell
# Replace /path/to/config with the absolute path to your wormhole.passwd file.
podman run --rm -it -p 8800:8800 \
  -v /path/to/config/wormhole.passwd:/config/wormhole.passwd:ro \
  quay.io/cwt/wormhole:<tag> \
  wormhole -a /config/wormhole.passwd
```

*(Note: You can use docker in place of podman for all examples.)*

-----

## Automatic IPv6 Detection

Wormhole can automatically detect when IPv6 becomes available on your system and restart the server to enable dual-stack support. This is especially useful when moving between networks where IPv6 availability changes.

To enable this feature, use the `--auto-ipv6` flag:

```shell
wormhole --auto-ipv6
```

When this flag is enabled, Wormhole will:
1. Periodically check for IPv6 availability
2. Automatically restart the server with dual-stack support when IPv6 becomes available
3. Continue to monitor for network changes

This feature is particularly useful for mobile users who move between networks with different IPv6 support.

-----

## License

MIT License (included in the source distribution)

-----

## Notice

  - This project is forked and converted to Mercurial from
    [WARP](https://github.com/devunt/warp) on GitHub.
  - Now we are back on GitHub again.


# Wormhole

**Wormhole** is a forward proxy without caching. You may use it for:

  - Modifying requests to look like they are originated from the IP
    address that *Wormhole* is running on.
  - Adding an authentication layer to the internet users in your
    organization.
  - Logging internet activities to your syslog server.
  - Blocking ads and other unwanted content.

-----

## Features

  - **Ad-blocking:** Wormhole can block domains based on a comprehensive list of ad-serving and tracking domains. You can create your own ad-block database or use the provided script to download and compile one from popular sources.
  - **Allowlist:** You can specify a list of domains that should never be blocked, ensuring that important services are always accessible.
  - **HTTP/1.1 Upgrade:** Automatically attempts to upgrade HTTP/1.0 requests to HTTP/1.1 to leverage modern web features and improve performance.
  - **IPv6 Prioritization:** Prefers IPv6 connections when available for faster and more modern networking.
  - **Security:** Includes safeguards to prevent proxying to private and reserved IP addresses, mitigating the risk of SSRF (Server-Side Request Forgery) attacks.
  - **High Performance:** Built with `asyncio` and can leverage `uvloop` or `winloop` for even better performance. The number of concurrent connections is dynamically adjusted based on system limits.

-----

## Dependency

  - Python \>= 3.11
  - `aiohttp`
  - `aiosqlite`
  - `loguru`
  - [uvloop](https://github.com/MagicStack/uvloop) (optional)
  - [winloop](https://github.com/Vizonex/Winloop) (optional for Windows)

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

You can also install the **development snapshot** using `pip` with
`mercurial`:

```shell
$ pip install hg+https://hg.sr.ht/~cwt/wormhole
```

Or install from your local clone:

```shell
$ hg clone https://hg.sr.ht/~cwt/wormhole
$ cd wormhole/
$ pip install -e .
```

You can also install the latest `tip` snapshot using the following
command:

```shell
$ pip install https://hg.sr.ht/~cwt/wormhole/archive/tip.tar.gz
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

### Ad-Blocker Usage

1.  **Update the ad-block database:**

    ```shell
    $ wormhole --update-ad-block-db ads.sqlite3
    ```

2.  **Run Wormhole with the ad-blocker enabled:**

    ```shell
    $ wormhole --ad-block-db ads.sqlite3
    ```

-----

## Command help

```shell
$ wormhole --help
```

The output will be similar to this:

```
usage: wormhole [-h] [-H HOST] [-p PORT] [-a AUTHENTICATION] [--allow-private] [-S SYSLOG_HOST] [-P SYSLOG_PORT] [-l] [-v] [--ad-block-db AD_BLOCK_DB] [--update-ad-block-db DB_PATH] [--allowlist ALLOWLIST]

Wormhole (3.1.0): Asynchronous I/O HTTP/S Proxy

options:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  Host address to bind [default: 0.0.0.0]
  -p PORT, --port PORT  Port to listen on [default: 8800]
  -a AUTHENTICATION, --authentication AUTHENTICATION
                        Path to authentication file (user:pass list)
  --allow-private       Allow proxying to private and reserved IP addresses (disabled by default)
  -S SYSLOG_HOST, --syslog-host SYSLOG_HOST
                        Syslog host or path (e.g., /dev/log)
  -P SYSLOG_PORT, --syslog-port SYSLOG_PORT
                        Syslog port [default: 514]
  -l, --license         Print license information and exit
  -v, --verbose         Increase verbosity (-v, -vv)

Ad-Blocker Options:
  --ad-block-db AD_BLOCK_DB
                        Path to the SQLite database file containing domains to block.
  --update-ad-block-db DB_PATH
                        Fetch public ad-block lists and compile them into a database file, then exit.
  --allowlist ALLOWLIST
                        Path to a file of domains to extend the default allowlist.
```

-----

## **Docker Image Usage**

Official images are available at [quay.io/cwt/wormhole](https://quay.io/repository/cwt/wormhole).

### **1. Pull the image**

Pull the desired version tag from Quay.io.

```shell
# Replace <tag> with a specific version, e.g., v3.1.2  
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

Create a file (e.g., `/path.to/config/wormhole.passwd`) on your host machine with username:password entries, one per line.

```text
user1:password1
user2:anotherpassword
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

## License

MIT License (included in the source distribution)

-----

## Notice

  - This project is forked and converted to Mercurial from
    [WARP](https://github.com/devunt/warp) on GitHub.
  - Authentication file contains `username` and `password` in **plain
    text**, keep it secret\!

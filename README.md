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

## Docker Image Usage

### Run without authentication

```shell
$ docker pull bashell/wormhole
$ docker run -d -p 8800:8800 bashell/wormhole
```

### Run with authentication

  - Create an empty directory on your docker host
  - Create an authentication file that contains username and password in
    this format `username:password`
  - Link that directory to the container via option `-v` and also run
    wormhole container with option `-a /path/to/authentication_file`

Example:

```shell
$ docker pull bashell/wormhole
$ mkdir -p /path/to/dir
$ echo "user1:password1" > /path/to/dir/wormhole.passwd
$ docker run -d -v /path/to/dir:/opt/wormhole \
  -p 8800:8800 bashell/wormhole \
  -a /opt/wormhole/wormhole.passwd
```

-----

## License

MIT License (included in the source distribution)

-----

## Notice

  - This project is forked and converted to Mercurial from
    [WARP](https://github.com/devunt/warp) on GitHub.
  - Authentication file contains `username` and `password` in **plain
    text**, keep it secret\!

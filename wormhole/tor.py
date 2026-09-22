"""Private Tor daemon management and SOCKS5 transport for Wormhole.

Wormhole never trusts a pre-existing SOCKS listener on ``9050``/``9150``: it
spawns its own ``tor`` process on random loopback ports with a private data
directory, then routes outbound streams through it with ``python-socks``.

The optional dependencies (``stem`` and ``python_socks``) are imported
lazily so Wormhole keeps working when the ``tor`` extra is not installed.
"""

from .context import RequestContext
from .logger import logger, format_log_message as flm
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
import asyncio
import json
import os
import re
import shutil
import socket
import subprocess
import sys

# --- Constants ---
MIN_TOR_VERSION: tuple[int, int, int] = (0, 4, 8)
DEFAULT_BOOTSTRAP_TIMEOUT: int = 90
SNOWFLAKE_BOOTSTRAP_TIMEOUT: int = 120
# SOCKS connect budgets. Onion rendezvous (especially the first descriptor
# fetch) can exceed tor's default two-minute SocksTimeout, so the daemon is
# configured with a larger SocksTimeout and onion streams get a longer
# client-side budget than clearnet streams.
CLEARNET_CONNECT_TIMEOUT: float = 60.0
ONION_CONNECT_TIMEOUT: float = 250.0
TOR_SOCKS_TIMEOUT: int = 240
LOG_RING_SIZE: int = 200

# BridgeDB Moat endpoints follow Tor Browser's Moat client. They are
# best-effort: on any failure the rung is skipped and the operator can pass
# --tor-bridge instead.
MOAT_BASE_URL: str = "https://bridges.torproject.org/moat"
MOAT_BUILTIN_PATH: str = "/circumvention/builtin"

# Snowflake uses the well-known default bridge and broker configuration.
SNOWFLAKE_BROKER_URL: str = "https://snowflake-broker.torproject.net/"
SNOWFLAKE_FRONT: str = "cdn.sstatic.net"
SNOWFLAKE_DEFAULT_BRIDGE: str = (
    "snowflake 192.0.2.4:1 2B280B23E1107BB62ABFC40DDCC8824814F80A72"
)

PT_BINARY_NAMES: dict[str, tuple[str, ...]] = {
    "obfs4": ("lyrebird", "obfs4proxy"),
    "snowflake": ("snowflake-client",),
    "webtunnel": ("webtunnel-client",),
}

TOR_VERSION_PATTERN = re.compile(
    r"tor version (\d+)\.(\d+)\.(\d+)", re.IGNORECASE
)
BOOTSTRAP_PERCENT_PATTERN = re.compile(r"bootstrapped (\d+)%", re.IGNORECASE)
BRIDGE_LINE_PATTERN = re.compile(
    r"^(obfs4|snowflake|webtunnel)\s+", re.IGNORECASE
)

# --- Exceptions ---


class TorError(Exception):
    """Base exception for Tor integration errors."""


class TorUnavailableError(TorError):
    """Tor support cannot start (missing binary, extras, or PT)."""


class TorBootstrapError(TorError):
    """A single bootstrap rung (attempt) failed."""

    def __init__(self, reason: str, log_lines: Sequence[str]) -> None:
        """Store the classified reason and the captured tor log lines."""
        self.reason = reason
        self.log_lines = list(log_lines)
        super().__init__(reason)


@dataclass(frozen=True)
class AttemptFailure:
    """A failed bootstrap rung and its classified reason."""

    rung: str
    reason: str


class TorBlockedError(TorError):
    """Every bootstrap rung failed."""

    def __init__(
        self,
        failures: Sequence[AttemptFailure],
        no_connectivity: bool = False,
    ) -> None:
        """Store per-rung failures and the connectivity probe result."""
        self.failures = list(failures)
        self.no_connectivity = no_connectivity
        super().__init__("Tor could not bootstrap on this network.")

    def report_lines(self) -> list[str]:
        """Build the user-facing report shown when the ladder is exhausted."""
        lines: list[str] = []
        if self.no_connectivity:
            lines.append(
                "No internet connectivity: a plain HTTPS probe failed too, "
                "so Tor could not be tested."
            )
        else:
            lines.append("Tor could not bootstrap on this network.")
        for failure in self.failures:
            lines.append(f"  {failure.rung}: {failure.reason}")
        if not self.no_connectivity:
            lines.append(
                "Most likely your network blocks or heavily filters Tor. "
                "Options:"
            )
            lines.append('  - pass your own bridge:  --tor-bridge "obfs4 ..."')
            lines.append("  - verify with Tor Browser's built-in bridge test")
            lines.append("  - connect from another network or a VPN")
        return lines


# --- Data model ---


@dataclass(frozen=True)
class RungDefinition:
    """One attempt of the bootstrap ladder."""

    name: str
    transport: str | None
    uses_bridges: bool
    timeout: int
    bridges: tuple[str, ...] = ()
    pt_binary: Path | None = None


@dataclass(frozen=True)
class TorEndpoint:
    """A bootstrapped private tor daemon."""

    rung: str
    socks_url: str


# --- Active endpoint state (read by handler.py) ---

_ACTIVE_ENDPOINT: TorEndpoint | None = None


def set_active_endpoint(endpoint: TorEndpoint) -> None:
    """Register the endpoint used for all outbound Tor streams."""
    global _ACTIVE_ENDPOINT
    _ACTIVE_ENDPOINT = endpoint


def get_active_endpoint() -> TorEndpoint | None:
    """Return the active endpoint, if Tor mode is running."""
    return _ACTIVE_ENDPOINT


def is_tor_active() -> bool:
    """Return True when outbound traffic must use the Tor SOCKS proxy."""
    return _ACTIVE_ENDPOINT is not None


def clear_active_endpoint() -> None:
    """Forget the active endpoint (called during shutdown)."""
    global _ACTIVE_ENDPOINT
    _ACTIVE_ENDPOINT = None


# --- Binary and version discovery ---


def find_tor_binary(explicit: str | None) -> Path:
    """Locate the tor binary from an explicit path or ``PATH``.

    Raises:
        TorUnavailableError: If no usable binary can be found.
    """
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise TorUnavailableError(f"tor binary not found: {explicit}")
        return path
    name = "tor.exe" if sys.platform == "win32" else "tor"
    found = shutil.which(name)
    if found is None:
        raise TorUnavailableError(
            "could not find the tor binary in PATH; install tor with your "
            "package manager or pass --tor-binary PATH"
        )
    return Path(found)


def parse_tor_version(output: str) -> tuple[int, int, int]:
    """Parse the output of ``tor --version``.

    Raises:
        TorUnavailableError: If the version string cannot be parsed.
    """
    match = TOR_VERSION_PATTERN.search(output)
    if match is None:
        raise TorUnavailableError("could not parse the tor version output")
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def read_tor_version(binary: Path) -> tuple[int, int, int]:
    """Run ``tor --version`` and return the parsed version tuple.

    Raises:
        TorUnavailableError: If tor cannot be executed or reports no version.
    """
    try:
        result = subprocess.run(
            [str(binary), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except OSError as e:
        raise TorUnavailableError(f"could not execute tor: {e}") from e
    if result.returncode != 0:
        raise TorUnavailableError(
            f"tor --version failed with exit code {result.returncode}"
        )
    return parse_tor_version(result.stdout)


def version_string(version: tuple[int, int, int]) -> str:
    """Format a version tuple for log messages."""
    return ".".join(str(part) for part in version)


# --- Ports and pluggable transports ---


def allocate_loopback_ports(count: int = 2) -> list[int]:
    """Allocate distinct free TCP ports bound to 127.0.0.1."""
    ports: list[int] = []
    while len(ports) < count:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        if port not in ports:
            ports.append(port)
    return ports


def prepare_data_dir(root: Path, name: str) -> Path:
    """Create the per-rung data directory with private permissions.

    Tor creates its data directory but not missing parents, so Wormhole must
    prepare ``<root>/<name>`` (and ``root`` itself) beforehand. On POSIX the
    directory is restricted to the owner, protecting guard and bridge state.
    """
    path = root / name
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        path.chmod(0o700)
    return path


def find_pt_binary(
    transport: str,
    tor_binary: Path,
    pt_dir: Path | None = None,
) -> Path | None:
    """Find a pluggable-transport binary for the given transport.

    Search order: ``--tor-pt-dir``, the directory of the tor binary
    (Expert Bundle / Tor Browser layout), then ``PATH``.
    """
    names = PT_BINARY_NAMES.get(transport, ())
    candidates: list[Path] = []
    if pt_dir is not None:
        candidates.extend(pt_dir / name for name in names)
    candidates.extend(tor_binary.parent / name for name in names)
    for name in names:
        found = shutil.which(name)
        if found is not None:
            candidates.append(Path(found))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def transport_from_bridge_line(line: str) -> str | None:
    """Return the transport name of a bridge line, if it is supported."""
    match = BRIDGE_LINE_PATTERN.match(line.strip())
    if match is None:
        return None
    return match.group(1).lower()


def load_bridge_lines(path: Path) -> list[str]:
    """Read bridge lines from a file, skipping blanks and comments.

    Raises:
        TorUnavailableError: If the bridge file cannot be read.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise TorUnavailableError(f"could not read bridge file: {e}") from e
    lines: list[str] = []
    for raw_line in raw.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


# --- Bootstrap ladder planning ---


def plan_rungs(
    *,
    tor_binary: Path,
    bridges: Sequence[str],
    no_bridges: bool,
    snowflake: bool,
    pt_dir: Path | None,
    timeout: int,
) -> list[RungDefinition]:
    """Build the ordered bootstrap ladder for the current configuration."""
    if no_bridges:
        return [RungDefinition("direct", None, False, timeout)]

    if bridges:
        transport = transport_from_bridge_line(bridges[0]) or "obfs4"
        plugin = find_pt_binary(transport, tor_binary, pt_dir)
        if transport in PT_BINARY_NAMES and plugin is None:
            names = ", ".join(PT_BINARY_NAMES[transport])
            raise TorUnavailableError(
                f"bridge transport '{transport}' requires one of: {names}; "
                "install the pluggable transport or remove the bridge"
            )
        return [
            RungDefinition(
                transport,
                transport,
                True,
                timeout,
                tuple(bridges),
                plugin,
            )
        ]

    rungs = [RungDefinition("direct", None, False, timeout)]

    obfs4_binary = find_pt_binary("obfs4", tor_binary, pt_dir)
    if obfs4_binary is not None:
        rungs.append(
            RungDefinition("obfs4", "obfs4", True, timeout, (), obfs4_binary)
        )
    else:
        logger.info(
            "obfs4 bridges unavailable: install lyrebird (or obfs4proxy) "
            "to enable that rung."
        )

    if snowflake:
        snowflake_binary = find_pt_binary("snowflake", tor_binary, pt_dir)
        if snowflake_binary is None:
            logger.warning(
                "--tor-snowflake requested but snowflake-client was not "
                "found; skipping that rung."
            )
        else:
            snowflake_timeout = timeout
            if timeout == DEFAULT_BOOTSTRAP_TIMEOUT:
                snowflake_timeout = SNOWFLAKE_BOOTSTRAP_TIMEOUT
            rungs.append(
                RungDefinition(
                    "snowflake",
                    "snowflake",
                    True,
                    snowflake_timeout,
                    (SNOWFLAKE_DEFAULT_BRIDGE,),
                    snowflake_binary,
                )
            )

    webtunnel_binary = find_pt_binary("webtunnel", tor_binary, pt_dir)
    if webtunnel_binary is not None:
        rungs.append(
            RungDefinition(
                "webtunnel", "webtunnel", True, timeout, (), webtunnel_binary
            )
        )

    return rungs


def _client_transport_plugin(rung: RungDefinition) -> str | None:
    """Build the tor ``ClientTransportPlugin`` line for a bridge rung."""
    if rung.transport is None or rung.pt_binary is None:
        return None
    if rung.transport == "snowflake":
        return (
            f"snowflake exec {rung.pt_binary} "
            f"-url {SNOWFLAKE_BROKER_URL} -front {SNOWFLAKE_FRONT}"
        )
    return f"{rung.transport} exec {rung.pt_binary}"


def build_tor_config(
    rung: RungDefinition,
    *,
    data_dir: Path,
    socks_port: int,
    control_port: int,
    isolate_dest: bool,
) -> dict[str, Any]:
    """Build the torrc-style configuration for one rung.

    Raises:
        TorBootstrapError: If a bridge rung has no bridge lines yet.
    """
    socks_listener = f"127.0.0.1:{socks_port}"
    if isolate_dest:
        socks_listener += " IsolateDestAddr"

    config: dict[str, Any] = {
        "SocksPort": socks_listener,
        "ControlPort": f"127.0.0.1:{control_port}",
        "CookieAuthentication": "1",
        "DataDirectory": str(data_dir / rung.name),
        "ClientOnly": "1",
        "SafeSocks": "1",
        "SocksTimeout": str(TOR_SOCKS_TIMEOUT),
        "Log": ["notice stdout"],
    }

    if rung.uses_bridges:
        if not rung.bridges:
            raise TorBootstrapError(
                "no bridge lines available for this rung", []
            )
        config["UseBridges"] = "1"
        config["Bridge"] = list(rung.bridges)
        plugin = _client_transport_plugin(rung)
        if plugin is not None:
            config["ClientTransportPlugin"] = [plugin]

    return config


# --- BridgeDB Moat client ---


def _flatten_strings(value: Any) -> list[str]:
    """Recursively collect strings from parsed JSON values."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        collected: list[str] = []
        for item in value:
            collected.extend(_flatten_strings(item))
        return collected
    if isinstance(value, dict):
        collected = []
        for item in value.values():
            collected.extend(_flatten_strings(item))
        return collected
    return []


def extract_bridge_lines(text: str, transport: str) -> list[str]:
    """Extract unique bridge lines for a transport from a Moat response."""
    candidates: list[str] = []
    try:
        decoded: Any = json.loads(text)
    except json.JSONDecodeError:
        decoded = None
    if decoded is not None:
        candidates.extend(_flatten_strings(decoded))
    candidates.extend(text.splitlines())

    pattern = re.compile(rf"^{re.escape(transport)}\s+\S+", re.IGNORECASE)
    lines: list[str] = []
    for candidate in candidates:
        cleaned = candidate.strip()
        if pattern.match(cleaned) and cleaned not in lines:
            lines.append(cleaned)
    return lines


async def fetch_bridges_from_moat(
    transport: str, timeout: float = 10.0
) -> list[str]:
    """Fetch default bridges for a transport from BridgeDB's Moat API.

    This is best-effort: any failure returns an empty list so the caller can
    fall back to a clear report instead of crashing.
    """
    try:
        import aiohttp
    except ImportError:
        logger.warning("aiohttp is required to fetch bridges from BridgeDB.")
        return []

    url = f"{MOAT_BASE_URL}{MOAT_BUILTIN_PATH}"
    try:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=client_timeout) as session:
            async with session.post(
                url, json={"transport": transport}
            ) as response:
                response.raise_for_status()
                text = await response.text()
    except Exception as e:
        logger.warning(
            f"Could not fetch {transport} bridges from BridgeDB: {e}"
        )
        return []
    return extract_bridge_lines(text, transport)


# --- Failure classification ---


def _bootstrap_progress(log_lines: Sequence[str]) -> str:
    """Return a `` (stuck at N%)`` suffix based on captured tor logs."""
    highest = -1
    for line in log_lines:
        match = BOOTSTRAP_PERCENT_PATTERN.search(line)
        if match is not None:
            highest = max(highest, int(match.group(1)))
    if highest < 0:
        return ""
    return f" (stuck at {highest}%)"


def classify_bootstrap_failure(log_lines: Sequence[str]) -> str:
    """Classify captured tor log lines into an actionable reason."""
    if not log_lines:
        return "bootstrap timed out"
    joined = "\n".join(log_lines).lower()
    progress = _bootstrap_progress(log_lines)

    if "couldn't create private data directory" in joined or (
        "error creating directory" in joined
    ):
        return f"could not create the Tor data directory{progress}"
    if any(
        name in joined
        for name in (
            "lyrebird",
            "obfs4proxy",
            "snowflake-client",
            "webtunnel-client",
        )
    ) and (
        "no such file or directory" in joined
        or "cannot exec" in joined
        or "failed to exec" in joined
    ):
        return f"pluggable transport binary could not be executed{progress}"
    if "cannot exec" in joined or "failed to exec" in joined:
        return f"could not execute a helper binary{progress}"
    if "no snowflake proxies" in joined or (
        "snowflake" in joined and "broker" in joined
    ):
        return (
            "snowflake broker or proxies unreachable "
            f"(WebRTC/UDP likely blocked){progress}"
        )
    if "failed to connect to bridge" in joined or (
        "bridge" in joined and "connection" in joined
    ):
        return f"bridge connections failed{progress}"
    if (
        "tls error" in joined
        or "handshake" in joined
        or "certificate" in joined
    ):
        return f"TLS interception or relay blocking{progress}"
    if "no route to host" in joined:
        return f"relay connections filtered (no route to host){progress}"
    if "connection refused" in joined:
        return f"relay connections refused{progress}"
    if "connection timed out" in joined or "timeout" in joined:
        return f"relay connections timed out{progress}"
    return f"bootstrap timed out{progress}"


# --- Process launch (stem) ---


def _check_tor_dependencies() -> None:
    """Ensure the optional ``tor`` extra is installed.

    Raises:
        TorUnavailableError: If stem or python-socks cannot be imported.
    """
    try:
        import python_socks.async_.asyncio  # noqa: F401
        import stem.process  # noqa: F401
    except ImportError as e:
        raise TorUnavailableError(
            "Tor support requires the optional dependencies; install them "
            "with: pip install 'wormhole-proxy[tor]'"
        ) from e


def _launch_tor_process(
    binary: Path,
    config: dict[str, Any],
    timeout: int,
    log_lines: list[str],
) -> subprocess.Popen:
    """Launch tor and wait until it reports 100% bootstrap.

    Raises:
        TorBootstrapError: If tor exits or fails to bootstrap in time.
    """
    import stem.process

    def handle_message(message: str) -> None:
        log_lines.append(message)
        if len(log_lines) > LOG_RING_SIZE:
            del log_lines[:-LOG_RING_SIZE]
        logger.debug(message)

    try:
        return stem.process.launch_tor_with_config(
            config=config,
            tor_cmd=str(binary),
            take_ownership=True,
            timeout=timeout,
            completion_percent=100,
            init_msg_handler=handle_message,
        )
    except Exception as e:
        raise TorBootstrapError(
            classify_bootstrap_failure(log_lines), log_lines
        ) from e


def default_data_dir() -> Path:
    """Return the platform-specific persistent Tor state directory."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "wormhole" / "tor"
        return Path.home() / "AppData" / "Local" / "wormhole" / "tor"
    if sys.platform == "darwin":
        return (
            Path.home() / "Library" / "Application Support" / "wormhole" / "tor"
        )
    base = os.environ.get("XDG_DATA_HOME")
    if base:
        return Path(base) / "wormhole" / "tor"
    return Path.home() / ".local" / "share" / "wormhole" / "tor"


# --- Tor-aware stream transport ---


def onion_connect_timeout(host: str) -> float:
    """Return the SOCKS connect budget for a host.

    Onion services get a longer budget because the first connection has to
    fetch the descriptor and complete a rendezvous, which can exceed tor's
    default SocksTimeout.
    """
    if host.lower().endswith(".onion"):
        return ONION_CONNECT_TIMEOUT
    return CLEARNET_CONNECT_TIMEOUT


async def _socks_connect(
    proxy_host: str,
    proxy_port: int,
    host: str,
    port: int,
    timeout: float,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect through a SOCKS5 proxy using python-socks.

    aiohttp_socks' ``open_connection`` is deprecated and never forwards a
    timeout to python-socks, which silently caps connects at 60 seconds and
    breaks onion rendezvous, so python-socks is used directly here.
    """
    from python_socks import ProxyType
    from python_socks.async_.asyncio import Proxy

    proxy = Proxy.create(
        proxy_type=ProxyType.SOCKS5,
        host=proxy_host,
        port=proxy_port,
        rdns=True,
    )
    sock = await proxy.connect(host, port, timeout=timeout)
    return await asyncio.open_connection(sock=sock)


async def tor_open_connection(
    host: str,
    port: int,
    context: RequestContext,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a stream through the active Tor SOCKS5 proxy.

    The hostname is passed to the proxy untouched (remote DNS), which is
    required for ``.onion`` addresses.

    Raises:
        TorError: If Tor mode is not active or the endpoint is malformed.
        OSError: If the SOCKS5 handshake fails or times out.
    """
    endpoint = _ACTIVE_ENDPOINT
    if endpoint is None:
        raise TorError("Tor mode is not active")
    parsed = urlparse(endpoint.socks_url)
    proxy_host = parsed.hostname or "127.0.0.1"
    proxy_port = parsed.port
    if proxy_port is None:
        raise TorError(f"invalid Tor SOCKS endpoint: {endpoint.socks_url}")

    timeout = onion_connect_timeout(host)
    logger.debug(
        flm(
            f"Opening Tor stream to {host}:{port} ({endpoint.rung} rung)",
            context.ident,
            context.verbose,
        )
    )
    try:
        return await _socks_connect(proxy_host, proxy_port, host, port, timeout)
    except TimeoutError as e:
        raise OSError(
            f"Tor stream to {host}:{port} timed out after {timeout:.0f}s"
        ) from e
    except Exception as e:
        raise OSError(f"Tor stream to {host}:{port} failed: {e}") from e


# --- Manager ---


class TorManager:
    """Own a private tor daemon for the lifetime of the proxy."""

    def __init__(
        self,
        *,
        binary: str | None = None,
        bridges: Sequence[str] = (),
        bridge_file: Path | None = None,
        data_dir: Path | None = None,
        pt_dir: Path | None = None,
        timeout: int = DEFAULT_BOOTSTRAP_TIMEOUT,
        no_bridges: bool = False,
        snowflake: bool = False,
        isolate_dest: bool = False,
        verbose: int = 0,
    ) -> None:
        """Store the configuration; nothing is started yet."""
        self.binary = binary
        self.bridges = tuple(bridges)
        self.bridge_file = bridge_file
        self.data_dir = data_dir if data_dir is not None else default_data_dir()
        self.pt_dir = pt_dir
        self.timeout = timeout
        self.no_bridges = no_bridges
        self.snowflake = snowflake
        self.isolate_dest = isolate_dest
        self.verbose = verbose
        self._binary: Path | None = None
        self._process: subprocess.Popen | None = None
        self._endpoint: TorEndpoint | None = None

    async def start(self) -> TorEndpoint:
        """Run the bootstrap ladder and return the first working rung.

        Raises:
            TorUnavailableError: Missing extras, binary, or bridge files.
            TorBlockedError: Every rung failed.
        """
        _check_tor_dependencies()
        binary = find_tor_binary(self.binary)
        version = await asyncio.to_thread(read_tor_version, binary)
        if version < MIN_TOR_VERSION:
            raise TorUnavailableError(
                f"tor {version_string(version)} is too old; version "
                f"{version_string(MIN_TOR_VERSION)} or newer is required"
            )
        self._binary = binary
        logger.info(
            flm(
                f"Using tor {version_string(version)} ({binary})",
                ident={"id": "000000", "client": "tor"},
                verbose=self.verbose,
            )
        )

        rungs = plan_rungs(
            tor_binary=binary,
            bridges=self._collect_bridges(),
            no_bridges=self.no_bridges,
            snowflake=self.snowflake,
            pt_dir=self.pt_dir,
            timeout=self.timeout,
        )
        failures: list[AttemptFailure] = []
        for index, rung in enumerate(rungs, start=1):
            logger.info(
                flm(
                    f"Tor attempt {index}/{len(rungs)} ({rung.name})...",
                    ident={"id": "000000", "client": "tor"},
                    verbose=self.verbose,
                )
            )
            try:
                endpoint = await self._run_rung(rung)
            except TorBootstrapError as e:
                failures.append(AttemptFailure(rung.name, e.reason))
                logger.warning(
                    flm(
                        f"Tor attempt ({rung.name}) failed: {e.reason}",
                        ident={"id": "000000", "client": "tor"},
                        verbose=self.verbose,
                    )
                )
                continue
            logger.info(
                flm(
                    f"Tor bootstrapped via '{rung.name}' rung "
                    f"({endpoint.socks_url}).",
                    ident={"id": "000000", "client": "tor"},
                    verbose=self.verbose,
                )
            )
            return endpoint

        no_connectivity = not await self.has_connectivity()
        raise TorBlockedError(failures, no_connectivity=no_connectivity)

    async def stop(self) -> None:
        """Terminate the owned tor daemon, if any."""
        process = self._process
        if process is None:
            return
        await asyncio.to_thread(self._terminate_process, process)
        self._process = None
        self._endpoint = None

    async def has_connectivity(self, timeout: float = 5.0) -> bool:
        """Probe a neutral HTTPS endpoint to distinguish no internet from
        Tor being blocked."""
        try:
            import aiohttp
        except ImportError:
            return False
        for url in ("https://check.torproject.org/", "https://1.1.1.1/"):
            try:
                client_timeout = aiohttp.ClientTimeout(total=timeout)
                async with aiohttp.ClientSession(
                    timeout=client_timeout
                ) as session:
                    async with session.get(url) as response:
                        if response.status < 500:
                            return True
            except Exception:
                continue
        return False

    def _collect_bridges(self) -> list[str]:
        """Merge bridge lines from the CLI with the bridge file, if any."""
        lines = list(self.bridges)
        if self.bridge_file is not None:
            lines.extend(load_bridge_lines(self.bridge_file))
        return lines

    async def _run_rung(self, rung: RungDefinition) -> TorEndpoint:
        """Resolve bridges if needed, then launch one rung in a worker."""
        if rung.uses_bridges and not rung.bridges:
            fetched = await fetch_bridges_from_moat(rung.transport or "obfs4")
            if not fetched:
                raise TorBootstrapError(
                    "could not obtain bridges from BridgeDB; pass "
                    "--tor-bridge",
                    [],
                )
            rung = replace(rung, bridges=tuple(fetched))

        await asyncio.to_thread(prepare_data_dir, self.data_dir, rung.name)
        ports = allocate_loopback_ports(2)
        if self._binary is None:
            raise TorUnavailableError("tor binary has not been resolved")
        config = build_tor_config(
            rung,
            data_dir=self.data_dir,
            socks_port=ports[0],
            control_port=ports[1],
            isolate_dest=self.isolate_dest,
        )
        # Run the launch on the event loop thread: stem's bootstrap timeout
        # only works in the main thread (it relies on signal.alarm) and would
        # otherwise be rejected or silently ignored. This blocks only during
        # startup, before the proxy begins accepting connections.
        return self._launch_rung(rung, config, ports[0])

    def _launch_rung(
        self,
        rung: RungDefinition,
        config: dict[str, Any],
        socks_port: int,
    ) -> TorEndpoint:
        """Launch tor for one rung; runs in a worker thread."""
        if self._binary is None:
            raise TorUnavailableError("tor binary has not been resolved")
        log_lines: list[str] = []
        process = _launch_tor_process(
            self._binary, config, rung.timeout, log_lines
        )
        self._process = process
        endpoint = TorEndpoint(
            rung=rung.name,
            socks_url=f"socks5://127.0.0.1:{socks_port}",
        )
        self._endpoint = endpoint
        return endpoint

    @staticmethod
    def _terminate_process(process: subprocess.Popen) -> None:
        """Terminate a tor process, escalating to SIGKILL after 10s."""
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

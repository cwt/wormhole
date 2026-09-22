#!/usr/bin/env python3
"""
Unit tests for the tor module.
"""

import asyncio
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from wormhole.context import RequestContext
from wormhole.handler import (
    _create_fastest_connection,
    _resolve_and_validate_host,
)
from wormhole.tor import (
    CLEARNET_CONNECT_TIMEOUT,
    DEFAULT_BOOTSTRAP_TIMEOUT,
    ONION_CONNECT_TIMEOUT,
    SNOWFLAKE_DEFAULT_BRIDGE,
    RungDefinition,
    TorBlockedError,
    TorBootstrapError,
    TorEndpoint,
    TorError,
    TorManager,
    TorUnavailableError,
    _check_tor_dependencies,
    _client_transport_plugin,
    _flatten_strings,
    _launch_tor_process,
    _socks_connect,
    allocate_loopback_ports,
    build_tor_config,
    classify_bootstrap_failure,
    clear_active_endpoint,
    default_data_dir,
    extract_bridge_lines,
    fetch_bridges_from_moat,
    find_pt_binary,
    find_tor_binary,
    get_active_endpoint,
    is_tor_active,
    load_bridge_lines,
    parse_tor_version,
    plan_rungs,
    prepare_data_dir,
    read_tor_version,
    set_active_endpoint,
    tor_open_connection,
    transport_from_bridge_line,
    version_string,
)


@pytest.fixture(autouse=True)
def reset_tor_state():
    """Ensure the global Tor endpoint does not leak between tests."""
    clear_active_endpoint()
    yield
    clear_active_endpoint()


def make_context() -> RequestContext:
    """Create a simple request context for tests."""
    return RequestContext({"id": "test123", "client": "127.0.0.1"}, 0)


class TestVersion:
    """Tests for tor version parsing."""

    def test_parse_tor_version_success(self):
        output = "Tor version 0.4.9.12.\n"
        assert parse_tor_version(output) == (0, 4, 9)

    def test_parse_tor_version_invalid(self):
        with pytest.raises(TorUnavailableError):
            parse_tor_version("no version here")

    def test_read_tor_version_success(self):
        result = subprocess.CompletedProcess(
            args=["tor", "--version"],
            returncode=0,
            stdout="Tor version 0.4.8.1.\n",
            stderr="",
        )
        with patch("wormhole.tor.subprocess.run", return_value=result):
            assert read_tor_version(Path("/usr/bin/tor")) == (0, 4, 8)

    def test_read_tor_version_failure(self):
        result = subprocess.CompletedProcess(
            args=["tor", "--version"],
            returncode=1,
            stdout="",
            stderr="boom",
        )
        with patch("wormhole.tor.subprocess.run", return_value=result):
            with pytest.raises(TorUnavailableError):
                read_tor_version(Path("/usr/bin/tor"))

    def test_read_tor_version_not_executable(self):
        with patch("wormhole.tor.subprocess.run", side_effect=OSError("nope")):
            with pytest.raises(TorUnavailableError):
                read_tor_version(Path("/usr/bin/tor"))


class TestBinaryDiscovery:
    """Tests for locating tor and pluggable-transport binaries."""

    def test_find_tor_binary_explicit(self, tmp_path):
        binary = tmp_path / "tor"
        binary.write_text("#!/bin/sh\n")
        assert find_tor_binary(str(binary)) == binary

    def test_find_tor_binary_explicit_missing(self, tmp_path):
        with pytest.raises(TorUnavailableError):
            find_tor_binary(str(tmp_path / "missing"))

    def test_find_tor_binary_from_path(self):
        with patch("wormhole.tor.shutil.which", return_value="/usr/bin/tor"):
            assert find_tor_binary(None) == Path("/usr/bin/tor")

    def test_find_tor_binary_not_found(self):
        with patch("wormhole.tor.shutil.which", return_value=None):
            with pytest.raises(TorUnavailableError):
                find_tor_binary(None)

    def test_find_pt_binary_in_pt_dir(self, tmp_path):
        pt_dir = tmp_path / "pt"
        pt_dir.mkdir()
        binary = pt_dir / "lyrebird"
        binary.write_text("")
        tor_binary = tmp_path / "tor"
        assert find_pt_binary("obfs4", tor_binary, pt_dir) == binary

    def test_find_pt_binary_next_to_tor(self, tmp_path):
        tor_binary = tmp_path / "tor"
        tor_binary.write_text("")
        binary = tmp_path / "obfs4proxy"
        binary.write_text("")
        assert find_pt_binary("obfs4", tor_binary, None) == binary

    def test_find_pt_binary_not_found(self, tmp_path):
        tor_binary = tmp_path / "tor"
        with patch("wormhole.tor.shutil.which", return_value=None):
            assert find_pt_binary("obfs4", tor_binary, None) is None

    def test_find_pt_binary_unknown_transport(self, tmp_path):
        assert find_pt_binary("meek", tmp_path / "tor", None) is None


class TestPorts:
    """Tests for loopback port allocation."""

    def test_allocate_loopback_ports(self):
        ports = allocate_loopback_ports(2)
        assert len(ports) == 2
        assert ports[0] != ports[1]
        for port in ports:
            assert 1024 <= port <= 65535


class TestBridgeParsing:
    """Tests for bridge-line handling."""

    def test_transport_from_bridge_line(self):
        assert (
            transport_from_bridge_line("obfs4 192.0.2.1:443 ABCD cert=xyz")
            == "obfs4"
        )
        assert (
            transport_from_bridge_line(SNOWFLAKE_DEFAULT_BRIDGE) == "snowflake"
        )
        assert (
            transport_from_bridge_line("webtunnel https://example.org/abc")
            == "webtunnel"
        )

    def test_transport_from_bridge_line_unsupported(self):
        assert transport_from_bridge_line("# comment") is None
        assert transport_from_bridge_line("garbage data") is None

    def test_extract_bridge_lines_plain(self):
        text = (
            "# comment\n"
            "obfs4 192.0.2.1:443 ABCD cert=xyz\n"
            "snowflake 192.0.2.4:1 ABCD\n"
            "obfs4 192.0.2.1:443 ABCD cert=xyz\n"
        )
        assert extract_bridge_lines(text, "obfs4") == [
            "obfs4 192.0.2.1:443 ABCD cert=xyz"
        ]

    def test_extract_bridge_lines_json(self):
        text = '{"bridges": ["obfs4 192.0.2.2:443 EFGH cert=abc"]}'
        assert extract_bridge_lines(text, "obfs4") == [
            "obfs4 192.0.2.2:443 EFGH cert=abc"
        ]

    def test_extract_bridge_lines_invalid_json(self):
        assert extract_bridge_lines("not json", "obfs4") == []

    def test_load_bridge_lines(self, tmp_path):
        bridge_file = tmp_path / "bridges.txt"
        bridge_file.write_text("# comment\n\nobfs4 192.0.2.3:443 IJKL\n")
        assert load_bridge_lines(bridge_file) == ["obfs4 192.0.2.3:443 IJKL"]

    def test_load_bridge_lines_missing(self, tmp_path):
        with pytest.raises(TorUnavailableError):
            load_bridge_lines(tmp_path / "missing.txt")


class TestRungPlanning:
    """Tests for bootstrap ladder planning."""

    def test_plan_rungs_no_bridges(self, tmp_path):
        rungs = plan_rungs(
            tor_binary=tmp_path / "tor",
            bridges=(),
            no_bridges=True,
            snowflake=True,
            pt_dir=None,
            timeout=30,
        )
        assert len(rungs) == 1
        assert rungs[0].name == "direct"
        assert rungs[0].timeout == 30

    def test_plan_rungs_explicit_bridge_missing_pt(self, tmp_path):
        with patch("wormhole.tor.find_pt_binary", return_value=None):
            with pytest.raises(TorUnavailableError):
                plan_rungs(
                    tor_binary=tmp_path / "tor",
                    bridges=("obfs4 192.0.2.1:443 ABCD",),
                    no_bridges=False,
                    snowflake=False,
                    pt_dir=None,
                    timeout=30,
                )

    def test_plan_rungs_explicit_bridge_with_pt(self, tmp_path):
        pt_binary = tmp_path / "lyrebird"
        with patch("wormhole.tor.find_pt_binary", return_value=pt_binary):
            rungs = plan_rungs(
                tor_binary=tmp_path / "tor",
                bridges=("obfs4 192.0.2.1:443 ABCD",),
                no_bridges=False,
                snowflake=False,
                pt_dir=None,
                timeout=30,
            )
        assert len(rungs) == 1
        assert rungs[0].name == "obfs4"
        assert rungs[0].bridges == ("obfs4 192.0.2.1:443 ABCD",)

    def test_plan_rungs_skips_missing_transports(self, tmp_path):
        with patch("wormhole.tor.find_pt_binary", return_value=None):
            rungs = plan_rungs(
                tor_binary=tmp_path / "tor",
                bridges=(),
                no_bridges=False,
                snowflake=True,
                pt_dir=None,
                timeout=DEFAULT_BOOTSTRAP_TIMEOUT,
            )
        assert [rung.name for rung in rungs] == ["direct"]

    def test_plan_rungs_full_ladder(self, tmp_path):
        def fake_find_pt(transport, tor_binary, pt_dir=None):
            return tmp_path / "pt-binary"

        with patch("wormhole.tor.find_pt_binary", new=fake_find_pt):
            rungs = plan_rungs(
                tor_binary=tmp_path / "tor",
                bridges=(),
                no_bridges=False,
                snowflake=True,
                pt_dir=None,
                timeout=DEFAULT_BOOTSTRAP_TIMEOUT,
            )
        assert [rung.name for rung in rungs] == [
            "direct",
            "obfs4",
            "snowflake",
            "webtunnel",
        ]
        snowflake_rung = rungs[2]
        assert snowflake_rung.bridges == (SNOWFLAKE_DEFAULT_BRIDGE,)
        assert snowflake_rung.timeout == 120

    def test_plan_rungs_snowflake_flag_without_binary(self, tmp_path):
        def fake_find_pt(transport, tor_binary, pt_dir=None):
            if transport == "snowflake":
                return None
            return tmp_path / "pt-binary"

        with patch("wormhole.tor.find_pt_binary", new=fake_find_pt):
            rungs = plan_rungs(
                tor_binary=tmp_path / "tor",
                bridges=(),
                no_bridges=False,
                snowflake=True,
                pt_dir=None,
                timeout=30,
            )
        assert [rung.name for rung in rungs] == [
            "direct",
            "obfs4",
            "webtunnel",
        ]


class TestConfigBuilding:
    """Tests for per-rung tor configuration."""

    def test_build_direct_config(self, tmp_path):
        rung = plan_rungs(
            tor_binary=tmp_path / "tor",
            bridges=(),
            no_bridges=True,
            snowflake=False,
            pt_dir=None,
            timeout=30,
        )[0]
        config = build_tor_config(
            rung,
            data_dir=tmp_path,
            socks_port=19050,
            control_port=19051,
            isolate_dest=False,
        )
        assert config["SocksPort"] == "127.0.0.1:19050"
        assert config["ControlPort"] == "127.0.0.1:19051"
        assert config["CookieAuthentication"] == "1"
        assert config["ClientOnly"] == "1"
        assert config["SafeSocks"] == "1"
        assert config["SocksTimeout"] == "240"
        assert "UseBridges" not in config
        assert Path(config["DataDirectory"]) == tmp_path / "direct"

    def test_build_direct_config_isolate_dest(self, tmp_path):
        rung = plan_rungs(
            tor_binary=tmp_path / "tor",
            bridges=(),
            no_bridges=True,
            snowflake=False,
            pt_dir=None,
            timeout=30,
        )[0]
        config = build_tor_config(
            rung,
            data_dir=tmp_path,
            socks_port=19050,
            control_port=19051,
            isolate_dest=True,
        )
        assert config["SocksPort"] == ("127.0.0.1:19050 IsolateDestAddr")

    def test_build_bridge_config(self, tmp_path):
        pt_binary = tmp_path / "lyrebird"
        with patch("wormhole.tor.find_pt_binary", return_value=pt_binary):
            rung = plan_rungs(
                tor_binary=tmp_path / "tor",
                bridges=("obfs4 192.0.2.1:443 ABCD",),
                no_bridges=False,
                snowflake=False,
                pt_dir=None,
                timeout=30,
            )[0]
        config = build_tor_config(
            rung,
            data_dir=tmp_path,
            socks_port=19050,
            control_port=19051,
            isolate_dest=False,
        )
        assert config["UseBridges"] == "1"
        assert config["Bridge"] == ["obfs4 192.0.2.1:443 ABCD"]
        assert config["ClientTransportPlugin"] == [f"obfs4 exec {pt_binary}"]

    def test_build_snowflake_config_plugin(self, tmp_path):
        snowflake_rung = None
        with patch(
            "wormhole.tor.find_pt_binary",
            return_value=tmp_path / "snowflake-client",
        ):
            rungs = plan_rungs(
                tor_binary=tmp_path / "tor",
                bridges=(),
                no_bridges=False,
                snowflake=True,
                pt_dir=None,
                timeout=30,
            )
        snowflake_rung = next(
            rung for rung in rungs if rung.name == "snowflake"
        )
        config = build_tor_config(
            snowflake_rung,
            data_dir=tmp_path,
            socks_port=19050,
            control_port=19051,
            isolate_dest=False,
        )
        plugin = config["ClientTransportPlugin"][0]
        assert plugin.startswith("snowflake exec ")
        assert "snowflake-broker.torproject.net" in plugin

    def test_build_bridge_config_requires_bridges(self, tmp_path):
        rung = RungDefinition(
            "obfs4",
            "obfs4",
            True,
            30,
            (),
            tmp_path / "lyrebird",
        )
        with pytest.raises(TorBootstrapError):
            build_tor_config(
                rung,
                data_dir=tmp_path,
                socks_port=19050,
                control_port=19051,
                isolate_dest=False,
            )


class TestClassification:
    """Tests for bootstrap log classification."""

    def test_empty_logs(self):
        assert classify_bootstrap_failure([]) == "bootstrap timed out"

    def test_connection_timeout(self):
        logs = [
            "Bootstrapped 10% (conn_done): Connected to a relay",
            "Problem bootstrapping: connection timed out",
        ]
        reason = classify_bootstrap_failure(logs)
        assert "timed out" in reason
        assert "stuck at 10%" in reason

    def test_tls_error(self):
        logs = ["TLS error while connecting to relay"]
        assert "TLS" in classify_bootstrap_failure(logs)

    def test_no_route(self):
        logs = ["connect to relay failed: no route to host"]
        assert "no route" in classify_bootstrap_failure(logs)

    def test_bridge_failure(self):
        logs = ["Failed to connect to bridge 192.0.2.1:443"]
        assert "bridge" in classify_bootstrap_failure(logs)

    def test_snowflake_broker(self):
        logs = ["snowflake: broker unreachable"]
        assert "snowflake" in classify_bootstrap_failure(logs)

    def test_transport_exec_failure(self):
        logs = ["lyrebird: No such file or directory"]
        assert "pluggable" in classify_bootstrap_failure(logs)


class TestActiveState:
    """Tests for the module-level active endpoint state."""

    def test_set_and_clear(self):
        assert is_tor_active() is False
        endpoint = TorEndpoint("direct", "socks5://127.0.0.1:19050")
        set_active_endpoint(endpoint)
        assert is_tor_active() is True
        clear_active_endpoint()
        assert is_tor_active() is False

    @pytest.mark.skipif(
        sys.platform != "linux", reason="XDG paths are Linux-only"
    )
    def test_default_data_dir_linux(self, monkeypatch):
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        assert default_data_dir() == (
            Path.home() / ".local" / "share" / "wormhole" / "tor"
        )

    @pytest.mark.skipif(
        sys.platform != "linux", reason="XDG paths are Linux-only"
    )
    def test_default_data_dir_xdg(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        assert default_data_dir() == tmp_path / "wormhole" / "tor"


class TestTorTransport:
    """Tests for the Tor-aware connection helpers."""

    async def test_tor_open_connection_inactive(self):
        with pytest.raises(TorError):
            await tor_open_connection("example.com", 80, make_context())

    async def test_create_fastest_connection_uses_tor(self):
        reader = MagicMock()
        writer = MagicMock()
        calls = {}

        async def fake_tor_open(host, port, context):
            calls["host"] = host
            calls["port"] = port
            return reader, writer

        with patch("wormhole.handler.tor_open_connection", new=fake_tor_open):
            set_active_endpoint(
                TorEndpoint("direct", "socks5://127.0.0.1:19050")
            )
            result = await _create_fastest_connection(
                [], 443, make_context(), hostname="example.com"
            )
        assert result == (reader, writer)
        assert calls == {"host": "example.com", "port": 443}

    async def test_create_fastest_connection_tor_requires_hostname(self):
        set_active_endpoint(TorEndpoint("direct", "socks5://127.0.0.1:19050"))
        with pytest.raises(OSError):
            await _create_fastest_connection([], 443, make_context())

    async def test_resolve_host_bypassed_in_tor_mode(self):
        set_active_endpoint(TorEndpoint("direct", "socks5://127.0.0.1:19050"))
        ips = await _resolve_and_validate_host(
            "example.com", make_context(), allow_private=False
        )
        assert ips == ["example.com"]


class TestManager:
    """Tests for the TorManager bootstrap ladder."""

    def make_manager(self) -> TorManager:
        return TorManager(binary="/usr/bin/tor", timeout=5)

    def patch_environment(self, monkeypatch):
        def fake_dependencies():
            return None

        def fake_find_binary(explicit):
            return Path("/usr/bin/tor")

        def fake_read_version(binary):
            return (0, 4, 9)

        def fake_plan(**kwargs):
            return [RungDefinition("direct", None, False, 5)]

        monkeypatch.setattr(
            "wormhole.tor._check_tor_dependencies", fake_dependencies
        )
        monkeypatch.setattr("wormhole.tor.find_tor_binary", fake_find_binary)
        monkeypatch.setattr("wormhole.tor.read_tor_version", fake_read_version)
        monkeypatch.setattr("wormhole.tor.plan_rungs", fake_plan)

    async def test_start_success(self, monkeypatch):
        self.patch_environment(monkeypatch)
        endpoint = TorEndpoint("direct", "socks5://127.0.0.1:19050")

        async def fake_run_rung(self, rung):
            return endpoint

        monkeypatch.setattr(TorManager, "_run_rung", fake_run_rung)
        manager = self.make_manager()
        assert await manager.start() == endpoint

    async def test_start_blocked(self, monkeypatch):
        self.patch_environment(monkeypatch)

        async def fake_run_rung(self, rung):
            raise TorBootstrapError(
                "relay connections timed out (stuck at 10%)", []
            )

        async def fake_has_connectivity(self, timeout=5.0):
            return True

        monkeypatch.setattr(TorManager, "_run_rung", fake_run_rung)
        monkeypatch.setattr(
            TorManager, "has_connectivity", fake_has_connectivity
        )
        manager = self.make_manager()
        with pytest.raises(TorBlockedError) as excinfo:
            await manager.start()
        assert excinfo.value.no_connectivity is False
        report = "\n".join(excinfo.value.report_lines())
        assert "direct:" in report
        assert "Most likely" in report

    async def test_start_blocked_without_connectivity(self, monkeypatch):
        self.patch_environment(monkeypatch)

        async def fake_run_rung(self, rung):
            raise TorBootstrapError("bootstrap timed out", [])

        async def fake_has_connectivity(self, timeout=5.0):
            return False

        monkeypatch.setattr(TorManager, "_run_rung", fake_run_rung)
        monkeypatch.setattr(
            TorManager, "has_connectivity", fake_has_connectivity
        )
        manager = self.make_manager()
        with pytest.raises(TorBlockedError) as excinfo:
            await manager.start()
        assert excinfo.value.no_connectivity is True
        report = "\n".join(excinfo.value.report_lines())
        assert "No internet connectivity" in report

    async def test_start_tor_too_old(self, monkeypatch):
        self.patch_environment(monkeypatch)

        def fake_read_version(binary):
            return (0, 4, 7)

        monkeypatch.setattr("wormhole.tor.read_tor_version", fake_read_version)
        manager = self.make_manager()
        with pytest.raises(TorUnavailableError):
            await manager.start()

    async def test_stop_without_process(self):
        manager = TorManager()
        await manager.stop()

    def test_terminate_process_already_exited(self):
        process = MagicMock()
        process.poll.return_value = 0
        TorManager._terminate_process(process)
        process.terminate.assert_not_called()

    def test_terminate_process_escalates_to_kill(self):
        process = MagicMock()
        process.poll.return_value = None
        process.wait.side_effect = [
            subprocess.TimeoutExpired("tor", 10),
            None,
        ]
        TorManager._terminate_process(process)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()


class FakeClientTimeout:
    """Stand-in for aiohttp.ClientTimeout."""

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


class FakeAiohttpResponse:
    """Stand-in for an aiohttp response context manager."""

    def __init__(self, status: int = 200, text: str = "") -> None:
        self.status = status
        self._text = text

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise RuntimeError(f"HTTP {self.status}")

    async def text(self) -> str:
        return self._text

    async def __aenter__(self) -> "FakeAiohttpResponse":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


class FakeAiohttpSession:
    """Stand-in for aiohttp.ClientSession with class-level behavior."""

    response: FakeAiohttpResponse | None = None
    error: Exception | None = None

    def __init__(self, **kwargs: Any) -> None:
        pass

    async def __aenter__(self) -> "FakeAiohttpSession":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    def post(self, url: str, json: dict | None = None):
        if self.error is not None:
            raise self.error
        return self.response

    def get(self, url: str):
        if self.error is not None:
            raise self.error
        return self.response


def make_fake_aiohttp() -> SimpleNamespace:
    """Build a fake aiohttp module for import-time patching."""
    return SimpleNamespace(
        ClientTimeout=FakeClientTimeout,
        ClientSession=FakeAiohttpSession,
    )


def patch_fake_stem(monkeypatch, launch) -> SimpleNamespace:
    """Install a fake stem.process module for import-time patching."""
    stem_process = SimpleNamespace(launch_tor_with_config=launch)
    stem_parent = SimpleNamespace(process=stem_process)
    monkeypatch.setitem(sys.modules, "stem", stem_parent)
    monkeypatch.setitem(sys.modules, "stem.process", stem_process)
    return stem_process


class TestTorInternals:
    """Additional coverage for internal helpers."""

    def test_get_active_endpoint(self):
        endpoint = TorEndpoint("direct", "socks5://127.0.0.1:19050")
        set_active_endpoint(endpoint)
        assert get_active_endpoint() == endpoint

    def test_version_string(self):
        assert version_string((0, 4, 9)) == "0.4.9"

    def test_find_pt_binary_from_path(self, tmp_path):
        binary = tmp_path / "lyrebird"
        binary.write_text("")
        with patch("wormhole.tor.shutil.which", return_value=str(binary)):
            assert find_pt_binary("obfs4", tmp_path / "tor", None) == binary

    def test_client_transport_plugin_without_transport(self):
        rung = RungDefinition("direct", None, False, 5)
        assert _client_transport_plugin(rung) is None

    def test_flatten_strings(self):
        assert _flatten_strings(42) == []
        assert _flatten_strings({"a": ["b", {"c": "d"}]}) == ["b", "d"]

    def test_classify_connection_refused(self):
        logs = ["connect to relay failed: connection refused"]
        assert "refused" in classify_bootstrap_failure(logs)

    def test_classify_data_directory_failure(self):
        logs = [
            "Error creating directory /home/user/.local/share/wormhole/tor/"
            "direct: No such file or directory"
        ]
        assert "data directory" in classify_bootstrap_failure(logs)

    def test_prepare_data_dir(self, tmp_path):
        path = prepare_data_dir(tmp_path / "wormhole" / "tor", "direct")
        assert path.is_dir()
        if sys.platform != "win32":
            assert (path.stat().st_mode & 0o777) == 0o700

    def test_default_data_dir_windows(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        assert default_data_dir() == tmp_path / "wormhole" / "tor"

    def test_default_data_dir_windows_without_localappdata(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.delenv("LOCALAPPDATA", raising=False)
        expected = Path.home() / "AppData" / "Local" / "wormhole" / "tor"
        assert default_data_dir() == expected

    def test_default_data_dir_darwin(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        expected = (
            Path.home() / "Library" / "Application Support" / "wormhole" / "tor"
        )
        assert default_data_dir() == expected


class TestDependencyChecks:
    """Tests for the optional dependency guard."""

    def test_check_dependencies_success(self, monkeypatch):
        def fake_launch(**kwargs):
            return None

        monkeypatch.setitem(sys.modules, "python_socks", SimpleNamespace())
        monkeypatch.setitem(
            sys.modules, "python_socks.async_", SimpleNamespace()
        )
        monkeypatch.setitem(
            sys.modules, "python_socks.async_.asyncio", SimpleNamespace()
        )
        patch_fake_stem(monkeypatch, fake_launch)
        _check_tor_dependencies()

    def test_check_dependencies_missing(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "python_socks.async_.asyncio", None)
        with pytest.raises(TorUnavailableError):
            _check_tor_dependencies()


class TestLaunchProcess:
    """Tests for the stem launch wrapper."""

    def test_launch_tor_process_success(self, monkeypatch, tmp_path):
        captured: dict[str, Any] = {}
        process = MagicMock()

        def fake_launch(**kwargs):
            captured.update(kwargs)
            kwargs["init_msg_handler"]("Bootstrapped 100% (done)")
            return process

        patch_fake_stem(monkeypatch, fake_launch)
        log_lines: list[str] = []
        result = _launch_tor_process(
            tmp_path / "tor", {"SocksPort": "127.0.0.1:1"}, 5, log_lines
        )
        assert result is process
        assert captured["tor_cmd"] == str(tmp_path / "tor")
        assert captured["take_ownership"] is True
        assert log_lines == ["Bootstrapped 100% (done)"]

    def test_launch_tor_process_ring_buffer(self, monkeypatch, tmp_path):
        process = MagicMock()

        def fake_launch(**kwargs):
            for _ in range(250):
                kwargs["init_msg_handler"]("line")
            return process

        patch_fake_stem(monkeypatch, fake_launch)
        log_lines: list[str] = []
        _launch_tor_process(
            tmp_path / "tor", {"SocksPort": "127.0.0.1:1"}, 5, log_lines
        )
        assert len(log_lines) == 200

    def test_launch_tor_process_failure(self, monkeypatch, tmp_path):
        def fake_launch(**kwargs):
            kwargs["init_msg_handler"]("connect failed: no route to host")
            raise RuntimeError("boom")

        patch_fake_stem(monkeypatch, fake_launch)
        with pytest.raises(TorBootstrapError) as excinfo:
            _launch_tor_process(
                tmp_path / "tor", {"SocksPort": "127.0.0.1:1"}, 5, []
            )
        assert "no route" in excinfo.value.reason


class TestMoatClient:
    """Tests for the best-effort BridgeDB Moat client."""

    async def test_fetch_bridges_success(self, monkeypatch):
        FakeAiohttpSession.response = FakeAiohttpResponse(
            status=200, text="obfs4 192.0.2.9:443 MMMM cert=abc"
        )
        FakeAiohttpSession.error = None
        monkeypatch.setitem(sys.modules, "aiohttp", make_fake_aiohttp())
        bridges = await fetch_bridges_from_moat("obfs4")
        assert bridges == ["obfs4 192.0.2.9:443 MMMM cert=abc"]

    async def test_fetch_bridges_http_error(self, monkeypatch):
        FakeAiohttpSession.response = FakeAiohttpResponse(status=500, text="")
        FakeAiohttpSession.error = None
        monkeypatch.setitem(sys.modules, "aiohttp", make_fake_aiohttp())
        assert await fetch_bridges_from_moat("obfs4") == []

    async def test_fetch_bridges_missing_aiohttp(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "aiohttp", None)
        assert await fetch_bridges_from_moat("obfs4") == []


class TestConnectivityProbe:
    """Tests for the no-internet probe."""

    async def test_has_connectivity_true(self, monkeypatch):
        FakeAiohttpSession.response = FakeAiohttpResponse(status=200)
        FakeAiohttpSession.error = None
        monkeypatch.setitem(sys.modules, "aiohttp", make_fake_aiohttp())
        manager = TorManager()
        assert await manager.has_connectivity(timeout=0.01) is True

    async def test_has_connectivity_false(self, monkeypatch):
        FakeAiohttpSession.response = None
        FakeAiohttpSession.error = RuntimeError("no network")
        monkeypatch.setitem(sys.modules, "aiohttp", make_fake_aiohttp())
        manager = TorManager()
        assert await manager.has_connectivity(timeout=0.01) is False

    async def test_has_connectivity_missing_aiohttp(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "aiohttp", None)
        manager = TorManager()
        assert await manager.has_connectivity() is False


class TestTorOpenConnection:
    """Tests for the Tor stream transport."""

    async def test_tor_open_connection_success(self, monkeypatch):
        set_active_endpoint(TorEndpoint("direct", "socks5://127.0.0.1:19050"))
        sentinel = (MagicMock(), MagicMock())
        calls: dict[str, Any] = {}

        async def fake_connect(proxy_host, proxy_port, host, port, timeout):
            calls.update(
                proxy_host=proxy_host,
                proxy_port=proxy_port,
                host=host,
                port=port,
                timeout=timeout,
            )
            return sentinel

        monkeypatch.setattr("wormhole.tor._socks_connect", fake_connect)
        result = await tor_open_connection("example.com", 443, make_context())
        assert result == sentinel
        assert calls == {
            "proxy_host": "127.0.0.1",
            "proxy_port": 19050,
            "host": "example.com",
            "port": 443,
            "timeout": CLEARNET_CONNECT_TIMEOUT,
        }

    async def test_tor_open_connection_onion_timeout(self, monkeypatch):
        set_active_endpoint(TorEndpoint("direct", "socks5://127.0.0.1:19050"))
        calls: dict[str, Any] = {}

        async def fake_connect(proxy_host, proxy_port, host, port, timeout):
            calls["timeout"] = timeout
            return MagicMock(), MagicMock()

        monkeypatch.setattr("wormhole.tor._socks_connect", fake_connect)
        await tor_open_connection(
            "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
            443,
            make_context(),
        )
        assert calls["timeout"] == ONION_CONNECT_TIMEOUT

    async def test_tor_open_connection_timeout(self, monkeypatch):
        set_active_endpoint(TorEndpoint("direct", "socks5://127.0.0.1:19050"))

        async def fake_connect(proxy_host, proxy_port, host, port, timeout):
            raise TimeoutError("slow")

        monkeypatch.setattr("wormhole.tor._socks_connect", fake_connect)
        with pytest.raises(OSError) as excinfo:
            await tor_open_connection("example.com", 443, make_context())
        assert "timed out" in str(excinfo.value)

    async def test_tor_open_connection_failure(self, monkeypatch):
        set_active_endpoint(TorEndpoint("direct", "socks5://127.0.0.1:19050"))

        async def fake_connect(proxy_host, proxy_port, host, port, timeout):
            raise OSError("refused")

        monkeypatch.setattr("wormhole.tor._socks_connect", fake_connect)
        with pytest.raises(OSError) as excinfo:
            await tor_open_connection("example.com", 443, make_context())
        assert "failed" in str(excinfo.value)

    async def test_socks_connect_uses_python_socks(self, monkeypatch):
        sentinel = (MagicMock(), MagicMock())
        captured: dict[str, Any] = {}

        class FakeProxy:
            @staticmethod
            def create(**kwargs):
                captured.update(kwargs)
                return FakeProxy()

            async def connect(self, host, port, timeout=None):
                captured["destination"] = (host, port, timeout)
                return "fake-socket"

        fake_asyncio_module = SimpleNamespace(Proxy=FakeProxy)
        fake_async_package = SimpleNamespace(asyncio=fake_asyncio_module)
        fake_package = SimpleNamespace(
            ProxyType=SimpleNamespace(SOCKS5="socks5"),
            async_=fake_async_package,
        )
        monkeypatch.setitem(sys.modules, "python_socks", fake_package)
        monkeypatch.setitem(
            sys.modules, "python_socks.async_", fake_async_package
        )
        monkeypatch.setitem(
            sys.modules, "python_socks.async_.asyncio", fake_asyncio_module
        )

        async def fake_open_connection(**kwargs):
            captured["open"] = kwargs
            return sentinel

        monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
        result = await _socks_connect(
            "127.0.0.1", 19050, "example.com", 80, 12.5
        )
        assert result == sentinel
        assert captured["host"] == "127.0.0.1"
        assert captured["port"] == 19050
        assert captured["rdns"] is True
        assert captured["destination"] == ("example.com", 80, 12.5)
        assert captured["open"] == {"sock": "fake-socket"}


class TestRunRung:
    """Tests for the per-rung execution path."""

    async def test_run_rung_fetches_bridges(self, monkeypatch, tmp_path):
        manager = TorManager(data_dir=tmp_path, timeout=5)
        manager._binary = tmp_path / "tor"
        fetched = ["obfs4 192.0.2.1:443 ABCD"]
        endpoint = TorEndpoint("obfs4", "socks5://127.0.0.1:19050")
        captured: dict[str, Any] = {}

        async def fake_fetch(transport, timeout=10.0):
            return fetched

        def fake_launch(self, rung, config, socks_port):
            captured["rung"] = rung
            captured["config"] = config
            return endpoint

        monkeypatch.setattr("wormhole.tor.fetch_bridges_from_moat", fake_fetch)
        monkeypatch.setattr(TorManager, "_launch_rung", fake_launch)
        rung = RungDefinition(
            "obfs4", "obfs4", True, 5, (), tmp_path / "lyrebird"
        )
        result = await manager._run_rung(rung)
        assert result == endpoint
        assert captured["rung"].bridges == tuple(fetched)
        assert captured["config"]["Bridge"] == fetched
        assert (tmp_path / "obfs4").is_dir()

    async def test_run_rung_without_bridges(self, monkeypatch, tmp_path):
        manager = TorManager(data_dir=tmp_path, timeout=5)
        manager._binary = tmp_path / "tor"

        async def fake_fetch(transport, timeout=10.0):
            return []

        monkeypatch.setattr("wormhole.tor.fetch_bridges_from_moat", fake_fetch)
        rung = RungDefinition(
            "obfs4", "obfs4", True, 5, (), tmp_path / "lyrebird"
        )
        with pytest.raises(TorBootstrapError):
            await manager._run_rung(rung)

    async def test_run_rung_without_binary(self, tmp_path):
        manager = TorManager(data_dir=tmp_path)
        rung = RungDefinition("direct", None, False, 5)
        with pytest.raises(TorUnavailableError):
            await manager._run_rung(rung)

    def test_launch_rung_stores_process(self, monkeypatch, tmp_path):
        manager = TorManager(data_dir=tmp_path)
        manager._binary = tmp_path / "tor"
        process = MagicMock()

        def fake_launch(binary, config, timeout, log_lines):
            return process

        monkeypatch.setattr("wormhole.tor._launch_tor_process", fake_launch)
        rung = RungDefinition("direct", None, False, 5)
        endpoint = manager._launch_rung(
            rung, {"SocksPort": "127.0.0.1:1"}, 19050
        )
        assert endpoint == TorEndpoint("direct", "socks5://127.0.0.1:19050")
        assert manager._process is process

    async def test_stop_terminates_process(self):
        manager = TorManager()
        process = MagicMock()
        process.poll.return_value = 0
        manager._process = process
        await manager.stop()
        assert manager._process is None

    def test_collect_bridges_merges_file(self, tmp_path):
        bridge_file = tmp_path / "bridges.txt"
        bridge_file.write_text("obfs4 192.0.2.3:443 WXYZ\n")
        manager = TorManager(
            bridges=["obfs4 192.0.2.1:443 ABCD"],
            bridge_file=bridge_file,
        )
        assert manager._collect_bridges() == [
            "obfs4 192.0.2.1:443 ABCD",
            "obfs4 192.0.2.3:443 WXYZ",
        ]

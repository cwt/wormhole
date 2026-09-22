#!/usr/bin/env python3
"""
Unit tests for the proxy module.
"""

import pytest
import sys
import asyncio
import types
import platform
from contextlib import contextmanager
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from argparse import Namespace
from wormhole.proxy import main, main_async
import wormhole.proxy as proxy_module


class TestMainAsync:
    """Test cases for the main_async function."""

    @pytest.mark.asyncio
    async def test_main_async_basic(self):
        """Test main_async with basic parameters."""
        # Create a mock args namespace
        args = Namespace(
            host="127.0.0.1",
            port=8080,
            allowlist=None,
            ad_block_db=None,
            auth=None,
            verbose=0,
            allow_private=False,
            syslog_host=None,
            syslog_port=514,
            blocklist=None,
            _test_mode=True,  # Prevent recursive calls in tests
            tor=False,
        )

        # Mock all the dependencies
        with (
            patch("wormhole.proxy.fastloop") as mock_fastloop,
            patch("wormhole.proxy.logger") as mock_logger,
            patch("wormhole.proxy.resolver") as mock_resolver,
            patch("wormhole.proxy.load_allowlist") as mock_load_allowlist,
            patch("wormhole.proxy.load_ad_block_db") as mock_load_ad_block_db,
            patch("wormhole.proxy.start_wormhole_server") as mock_start_server,
            patch("wormhole.proxy.asyncio.Event") as mock_event,
            patch("wormhole.proxy.asyncio.get_running_loop") as mock_get_loop,
            patch("wormhole.proxy.monitor_network_changes") as mock_monitor,
            patch("wormhole.proxy.is_ipv6_available") as mock_ipv6_available,
        ):

            # Set up mocks
            mock_server = AsyncMock()
            mock_start_server.return_value = mock_server

            mock_shutdown_event = Mock()
            mock_event.return_value = mock_shutdown_event
            mock_shutdown_event.wait = AsyncMock()

            # Make sure getattr(args, 'auto_ipv6', False) returns False
            delattr(args, "auto_ipv6") if hasattr(args, "auto_ipv6") else None

            mock_loop = Mock()
            mock_get_loop.return_value = mock_loop

            # Mock uvloop.__name__ attribute
            mock_fastloop.__name__ = "uvloop"

            # Mock network monitoring functions
            mock_ipv6_available.return_value = False
            mock_monitor.return_value = AsyncMock()

            # Call the function
            await main_async(args)

            # Verify the calls
            mock_resolver.initialize.assert_called_once_with(verbose=0)
            mock_start_server.assert_called_once_with(
                "127.0.0.1", 8080, None, 0, False, dual_stack=False
            )
            mock_shutdown_event.wait.assert_awaited_once()
            mock_server.close.assert_called_once()
            mock_server.wait_closed.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_main_async_with_allowlist(self):
        """Test main_async with allowlist."""
        # Create a mock args namespace
        args = Namespace(
            host="127.0.0.1",
            port=8080,
            allowlist="/path/to/allowlist",
            ad_block_db=None,
            auth=None,
            verbose=0,
            allow_private=False,
            syslog_host=None,
            syslog_port=514,
            blocklist=None,
            _test_mode=True,  # Prevent recursive calls in tests
            tor=False,
        )

        # Mock all the dependencies
        with (
            patch("wormhole.proxy.fastloop") as mock_fastloop,
            patch("wormhole.proxy.logger") as mock_logger,
            patch("wormhole.proxy.resolver") as mock_resolver,
            patch("wormhole.proxy.load_allowlist") as mock_load_allowlist,
            patch("wormhole.proxy.load_ad_block_db") as mock_load_ad_block_db,
            patch("wormhole.proxy.start_wormhole_server") as mock_start_server,
            patch("wormhole.proxy.asyncio.Event") as mock_event,
            patch("wormhole.proxy.asyncio.get_running_loop") as mock_get_loop,
            patch("wormhole.proxy.monitor_network_changes") as mock_monitor,
            patch("wormhole.proxy.is_ipv6_available") as mock_ipv6_available,
        ):

            # Set up mocks
            mock_load_allowlist.return_value = 10

            mock_server = AsyncMock()
            mock_start_server.return_value = mock_server

            mock_shutdown_event = Mock()
            mock_event.return_value = mock_shutdown_event
            mock_shutdown_event.wait = AsyncMock()

            # Make sure getattr(args, 'auto_ipv6', False) returns False
            delattr(args, "auto_ipv6") if hasattr(args, "auto_ipv6") else None

            mock_loop = Mock()
            mock_get_loop.return_value = mock_loop

            # Mock uvloop.__name__ attribute
            mock_fastloop.__name__ = "uvloop"

            # Mock network monitoring functions
            mock_ipv6_available.return_value = False
            mock_monitor.return_value = AsyncMock()

            # Call the function
            await main_async(args)

            # Verify the calls
            mock_load_allowlist.assert_called_once()
            mock_start_server.assert_called_once_with(
                "127.0.0.1", 8080, None, 0, False, dual_stack=False
            )

    @pytest.mark.asyncio
    async def test_main_async_with_ad_block_db(self):
        """Test main_async with ad-block database."""
        # Create a mock args namespace
        args = Namespace(
            host="127.0.0.1",
            port=8080,
            allowlist=None,
            ad_block_db="/path/to/adblock.db",
            auth=None,
            verbose=0,
            allow_private=False,
            syslog_host=None,
            syslog_port=514,
            blocklist=None,
            _test_mode=True,  # Prevent recursive calls in tests
            tor=False,
        )

        # Mock all the dependencies
        with (
            patch("wormhole.proxy.fastloop") as mock_fastloop,
            patch("wormhole.proxy.logger") as mock_logger,
            patch("wormhole.proxy.resolver") as mock_resolver,
            patch("wormhole.proxy.load_allowlist") as mock_load_allowlist,
            patch("wormhole.proxy.load_ad_block_db") as mock_load_ad_block_db,
            patch("wormhole.proxy.start_wormhole_server") as mock_start_server,
            patch("wormhole.proxy.asyncio.Event") as mock_event,
            patch("wormhole.proxy.asyncio.get_running_loop") as mock_get_loop,
            patch("wormhole.proxy.monitor_network_changes") as mock_monitor,
            patch("wormhole.proxy.is_ipv6_available") as mock_ipv6_available,
        ):

            # Set up mocks
            mock_load_ad_block_db.return_value = 100

            mock_server = AsyncMock()
            mock_start_server.return_value = mock_server

            mock_shutdown_event = Mock()
            mock_event.return_value = mock_shutdown_event
            mock_shutdown_event.wait = AsyncMock()

            # Make sure getattr(args, 'auto_ipv6', False) returns False
            delattr(args, "auto_ipv6") if hasattr(args, "auto_ipv6") else None

            mock_loop = Mock()
            mock_get_loop.return_value = mock_loop

            # Mock uvloop.__name__ attribute
            mock_fastloop.__name__ = "uvloop"

            # Mock network monitoring functions
            mock_ipv6_available.return_value = False
            mock_monitor.return_value = AsyncMock()

            # Call the function
            await main_async(args)

            # Verify the calls
            mock_load_ad_block_db.assert_called_once()
            mock_start_server.assert_called_once_with(
                "127.0.0.1", 8080, None, 0, False, dual_stack=False
            )

    @pytest.mark.asyncio
    async def test_main_async_with_blocklist(self):
        """Test main_async with blocklist."""
        # Create a mock args namespace
        args = Namespace(
            host="127.0.0.1",
            port=8080,
            allowlist=None,
            ad_block_db=None,
            auth=None,
            verbose=0,
            allow_private=False,
            syslog_host=None,
            syslog_port=514,
            blocklist="/path/to/blocklist",
            _test_mode=True,  # Prevent recursive calls in tests
            tor=False,
        )

        # Mock all the dependencies
        with (
            patch("wormhole.proxy.fastloop") as mock_fastloop,
            patch("wormhole.proxy.logger") as mock_logger,
            patch("wormhole.proxy.resolver") as mock_resolver,
            patch("wormhole.proxy.load_blocklist") as mock_load_blocklist,
            patch("wormhole.proxy.start_wormhole_server") as mock_start_server,
            patch("wormhole.proxy.asyncio.Event") as mock_event,
            patch("wormhole.proxy.asyncio.get_running_loop") as mock_get_loop,
            patch("wormhole.proxy.monitor_network_changes") as mock_monitor,
            patch("wormhole.proxy.is_ipv6_available") as mock_ipv6_available,
        ):

            # Set up mocks
            mock_load_blocklist.return_value = 5

            mock_server = AsyncMock()
            mock_start_server.return_value = mock_server

            mock_shutdown_event = Mock()
            mock_event.return_value = mock_shutdown_event
            mock_shutdown_event.wait = AsyncMock()

            # Make sure getattr(args, 'auto_ipv6', False) returns False
            delattr(args, "auto_ipv6") if hasattr(args, "auto_ipv6") else None

            mock_loop = Mock()
            mock_get_loop.return_value = mock_loop

            # Mock uvloop.__name__ attribute
            mock_fastloop.__name__ = "uvloop"

            # Mock network monitoring functions
            mock_ipv6_available.return_value = False
            mock_monitor.return_value = AsyncMock()

            # Call the function
            await main_async(args)

            # Verify the calls
            mock_load_blocklist.assert_called_once()
            mock_start_server.assert_called_once_with(
                "127.0.0.1", 8080, None, 0, False, dual_stack=False
            )


class TestMain:
    """Test cases for the main function."""

    def test_main_license(self):
        """Test main with --license argument."""
        test_args = ["wormhole", "--license"]

        with patch.object(sys, "argv", test_args):
            with (
                patch("wormhole.proxy.ArgumentParser.parse_args") as mock_parse,
                patch("wormhole.proxy.Path") as mock_path,
                patch("builtins.print") as mock_print,
            ):

                mock_args = Mock()
                mock_args.license = True
                mock_args.auth_add = None
                mock_args.auth_mod = None
                mock_args.auth_del = None
                mock_args.update_ad_block_db = None
                mock_parse.return_value = mock_args

                # Mock Path properly
                mock_path_instance = MagicMock()

                def mock_div(self, other):
                    return MagicMock()

                mock_path_instance.__truediv__ = mock_div
                mock_path_instance.read_text.return_value = "License text"
                mock_path.return_value = mock_path_instance

                result = main()
                assert result == 0

    def test_main_auth_add(self):
        """Test main with --auth-add argument."""
        test_args = ["wormhole", "--auth-add", "/path/to/auth", "username"]

        with patch.object(sys, "argv", test_args):
            with (
                patch("wormhole.proxy.ArgumentParser.parse_args") as mock_parse,
                patch("wormhole.proxy.add_user") as mock_add_user,
            ):

                mock_args = Mock()
                mock_args.license = False
                mock_args.auth_add = ["/path/to/auth", "username"]
                mock_args.auth_mod = None
                mock_args.auth_del = None
                mock_args.update_ad_block_db = None
                mock_args.syslog_host = None
                mock_args.syslog_port = 514
                mock_args.verbose = 0
                mock_parse.return_value = mock_args

                mock_add_user.return_value = 0

                result = main()
                assert result == 0
                mock_add_user.assert_called_once_with(
                    "/path/to/auth", "username"
                )

    def test_main_auth_mod(self):
        """Test main with --auth-mod argument."""
        test_args = ["wormhole", "--auth-mod", "/path/to/auth", "username"]

        with patch.object(sys, "argv", test_args):
            with (
                patch("wormhole.proxy.ArgumentParser.parse_args") as mock_parse,
                patch("wormhole.proxy.modify_user") as mock_modify_user,
            ):

                mock_args = Mock()
                mock_args.license = False
                mock_args.auth_add = None
                mock_args.auth_mod = ["/path/to/auth", "username"]
                mock_args.auth_del = None
                mock_args.update_ad_block_db = None
                mock_args.syslog_host = None
                mock_args.syslog_port = 514
                mock_args.verbose = 0
                mock_parse.return_value = mock_args

                mock_modify_user.return_value = 0

                result = main()
                assert result == 0
                mock_modify_user.assert_called_once_with(
                    "/path/to/auth", "username"
                )

    def test_main_auth_del(self):
        """Test main with --auth-del argument."""
        test_args = ["wormhole", "--auth-del", "/path/to/auth", "username"]

        with patch.object(sys, "argv", test_args):
            with (
                patch("wormhole.proxy.ArgumentParser.parse_args") as mock_parse,
                patch("wormhole.proxy.delete_user") as mock_delete_user,
            ):

                mock_args = Mock()
                mock_args.license = False
                mock_args.auth_add = None
                mock_args.auth_mod = None
                mock_args.auth_del = ["/path/to/auth", "username"]
                mock_args.update_ad_block_db = None
                mock_args.syslog_host = None
                mock_args.syslog_port = 514
                mock_args.verbose = 0
                mock_parse.return_value = mock_args

                mock_delete_user.return_value = 0

                result = main()
                assert result == 0
                mock_delete_user.assert_called_once_with(
                    "/path/to/auth", "username"
                )

    def test_main_update_ad_block_db(self):
        """Test main with --update-ad-block-db argument."""
        test_args = ["wormhole", "--update-ad-block-db", "/path/to/adblock.db"]

        with patch.object(sys, "argv", test_args):
            with (
                patch("wormhole.proxy.ArgumentParser.parse_args") as mock_parse,
                patch("wormhole.proxy.setup_logger") as mock_setup_logger,
                patch("wormhole.proxy.update_database") as mock_update_db,
                patch("wormhole.proxy.asyncio.run") as mock_asyncio_run,
            ):

                mock_args = Mock()
                mock_args.license = False
                mock_args.auth_add = None
                mock_args.auth_mod = None
                mock_args.auth_del = None
                mock_args.update_ad_block_db = "/path/to/adblock.db"
                mock_args.allowlist = None
                mock_args.blocklist = None
                mock_args.syslog_host = None
                mock_args.syslog_port = 514
                mock_args.verbose = 0
                mock_args.auth = None  # Add the auth attribute
                mock_parse.return_value = mock_args

                mock_asyncio_run.return_value = None

                # Mock the event loop to avoid RuntimeError
                with patch("asyncio.get_event_loop") as mock_get_loop:
                    mock_loop = Mock()
                    mock_get_loop.return_value = mock_loop
                    mock_loop.is_running.return_value = False

                    result = main()
                    assert result == 0
                    mock_setup_logger.assert_called_once_with(
                        None, 514, 0, async_mode=False
                    )
                    mock_asyncio_run.assert_called_once()

    def test_main_update_ad_block_db_with_blocklist(self):
        """Test main with --update-ad-block-db argument including blocklist."""
        test_args = [
            "wormhole",
            "--update-ad-block-db",
            "/path/to/adblock.db",
            "--blocklist",
            "/path/to/blocklist",
        ]

        with patch.object(sys, "argv", test_args):
            with (
                patch("wormhole.proxy.ArgumentParser.parse_args") as mock_parse,
                patch("wormhole.proxy.setup_logger") as mock_setup_logger,
                patch("wormhole.proxy.update_database") as mock_update_db,
                patch("wormhole.proxy.asyncio.run") as mock_asyncio_run,
            ):

                mock_args = Mock()
                mock_args.license = False
                mock_args.auth_add = None
                mock_args.auth_mod = None
                mock_args.auth_del = None
                mock_args.update_ad_block_db = "/path/to/adblock.db"
                mock_args.allowlist = None
                mock_args.blocklist = "/path/to/blocklist"
                mock_args.syslog_host = None
                mock_args.syslog_port = 514
                mock_args.verbose = 0
                mock_args.auth = None  # Add the auth attribute
                mock_parse.return_value = mock_args

                mock_asyncio_run.return_value = None

                # Mock the event loop to avoid RuntimeError
                with patch("asyncio.get_event_loop") as mock_get_loop:
                    mock_loop = Mock()
                    mock_get_loop.return_value = mock_loop
                    mock_loop.is_running.return_value = False

                    result = main()
                    assert result == 0
                    mock_setup_logger.assert_called_once_with(
                        None, 514, 0, async_mode=False
                    )
                    mock_asyncio_run.assert_called_once()

    def test_main_server_mode(self):
        """Test main in server mode."""
        test_args = ["wormhole"]

        with patch.object(sys, "argv", test_args):
            with (
                patch("wormhole.proxy.ArgumentParser.parse_args") as mock_parse,
                patch("wormhole.proxy.fastloop") as mock_fastloop,
                patch("wormhole.proxy.setup_logger") as mock_setup_logger,
                patch("wormhole.proxy.asyncio.run") as mock_asyncio_run,
            ):

                # Mock uvloop to not have the 'run' attribute, so it will use asyncio.run
                del mock_fastloop.run

                mock_args = Mock()
                mock_args.license = False
                mock_args.auth_add = None
                mock_args.auth_mod = None
                mock_args.auth_del = None
                mock_args.update_ad_block_db = None
                mock_args.host = "127.0.0.1"
                mock_args.port = 8080
                mock_args.syslog_host = None
                mock_args.syslog_port = 514
                mock_args.verbose = 0
                mock_args.auth = None
                mock_args.allowlist = None
                mock_args.ad_block_db = None
                mock_args.allow_private = False
                mock_args.tor = False
                mock_args.tor_binary = None
                mock_args.tor_bridge = None
                mock_args.tor_bridge_file = None
                mock_args.tor_timeout = 90
                mock_args.tor_data_dir = None
                mock_args.tor_pt_dir = None
                mock_args.tor_no_bridges = False
                mock_args.tor_snowflake = False
                mock_args.tor_isolate_dest = False
                mock_parse.return_value = mock_args

                # Mock asyncio.run to avoid actually running the async function
                mock_asyncio_run.return_value = None

                # Mock the event loop to avoid RuntimeError
                with patch("asyncio.get_event_loop") as mock_get_loop:
                    mock_loop = Mock()
                    mock_get_loop.return_value = mock_loop
                    mock_loop.is_running.return_value = False

                    result = main()
                    assert result == 0
                    mock_setup_logger.assert_called_once_with(
                        None, 514, 0, async_mode=True
                    )
                    mock_asyncio_run.assert_called_once()

    def test_main_invalid_port(self):
        """Test main with invalid port."""
        test_args = ["wormhole", "--port", "100"]

        with patch.object(sys, "argv", test_args):
            with patch(
                "wormhole.proxy.ArgumentParser.parse_args"
            ) as mock_parse:

                mock_args = Mock()
                mock_args.license = False
                mock_args.auth_add = None
                mock_args.auth_mod = None
                mock_args.auth_del = None
                mock_args.update_ad_block_db = None
                mock_args.port = 100  # Invalid port
                mock_args.syslog_host = None
                mock_args.syslog_port = 514
                mock_args.verbose = 0
                mock_args.auth = None  # Add the auth attribute
                mock_parse.return_value = mock_args

    def test_main_server_mode_uses_uvloop_run(self):
        """Server mode uses uvloop.run() when the loop exposes run()."""
        test_args = ["wormhole"]

        with patch.object(sys, "argv", test_args):
            with (
                patch("wormhole.proxy.ArgumentParser.parse_args") as mock_parse,
                patch("wormhole.proxy.fastloop") as mock_fastloop,
                patch("wormhole.proxy.setup_logger") as mock_setup_logger,
                patch("wormhole.proxy.asyncio.run") as mock_asyncio_run,
            ):
                # uvloop exposes a run() method -> _run_async uses it directly.
                mock_fastloop.run = Mock()

                mock_args = Mock()
                mock_args.license = False
                mock_args.auth_add = None
                mock_args.auth_mod = None
                mock_args.auth_del = None
                mock_args.update_ad_block_db = None
                mock_args.host = "127.0.0.1"
                mock_args.port = 8080
                mock_args.syslog_host = None
                mock_args.syslog_port = 514
                mock_args.verbose = 0
                mock_args.auth = None
                mock_args.allowlist = None
                mock_args.ad_block_db = None
                mock_args.allow_private = False
                mock_args.tor = False
                mock_args.tor_binary = None
                mock_args.tor_bridge = None
                mock_args.tor_bridge_file = None
                mock_args.tor_timeout = 90
                mock_args.tor_data_dir = None
                mock_args.tor_pt_dir = None
                mock_args.tor_no_bridges = False
                mock_args.tor_snowflake = False
                mock_args.tor_isolate_dest = False
                mock_parse.return_value = mock_args

                mock_asyncio_run.return_value = None

                with patch("asyncio.get_event_loop") as mock_get_loop:
                    mock_loop = Mock()
                    mock_get_loop.return_value = mock_loop
                    mock_loop.is_running.return_value = False

                    result = main()
                    assert result == 0
                    mock_fastloop.run.assert_called_once()
                    mock_asyncio_run.assert_not_called()

    def test_main_server_mode_uvloop_run_falls_back_to_asyncio(self):
        """If uvloop.run() raises, _run_async retries on stdlib asyncio."""
        test_args = ["wormhole"]

        def _boom(coro):
            raise RuntimeError("loop failed")

        with patch.object(sys, "argv", test_args):
            with (
                patch("wormhole.proxy.ArgumentParser.parse_args") as mock_parse,
                patch("wormhole.proxy.fastloop") as mock_fastloop,
                patch("wormhole.proxy.setup_logger") as mock_setup_logger,
                patch("wormhole.proxy.asyncio.run") as mock_asyncio_run,
                patch(
                    "wormhole.proxy.asyncio.set_event_loop_policy"
                ) as mock_set_policy,
            ):
                # uvloop.run raises -> must fall back to asyncio.run().
                mock_fastloop.run = Mock(side_effect=_boom)
                mock_fastloop.__name__ = "uvloop"

                mock_args = Mock()
                for attr in (
                    "license",
                    "auth_add",
                    "auth_mod",
                    "auth_del",
                    "update_ad_block_db",
                    "host",
                    "port",
                    "syslog_host",
                    "syslog_port",
                    "verbose",
                    "auth",
                    "allowlist",
                    "ad_block_db",
                    "allow_private",
                    "tor_binary",
                    "tor_bridge",
                    "tor_bridge_file",
                    "tor_data_dir",
                    "tor_pt_dir",
                    "tor_no_bridges",
                    "tor_snowflake",
                    "tor_isolate_dest",
                ):
                    setattr(mock_args, attr, None)
                mock_args.host = "127.0.0.1"
                mock_args.port = 8080
                mock_args.verbose = 0
                mock_args.license = False
                mock_args.tor = False
                mock_parse.return_value = mock_args

                mock_asyncio_run.return_value = None

                with patch("asyncio.get_event_loop") as mock_get_loop:
                    mock_loop = Mock()
                    mock_get_loop.return_value = mock_loop
                    mock_loop.is_running.return_value = False

                    result = main()
                    assert result == 0
                    mock_asyncio_run.assert_called_once()
                    mock_set_policy.assert_called_once_with(None)


class TestEventLoopSelection:
    """Tests for the event loop selection chain in wormhole.proxy.

    ``select_event_loop`` encapsulates the talyn -> uvloop/winloop -> stdlib
    asyncio selection. It is exercised directly under a patched environment
    (sys.platform, platform.machine, sys.version_info) with controlled
    availability of the optional loop packages, without reloading the module.
    """

    @contextmanager
    def _patched_selection(
        self,
        platform_name,
        machine,
        version,
        *,
        talyn=None,
        uvloop=None,
        winloop=None,
    ):
        # Control availability of the optional loop packages via sys.modules:
        #   True  -> inject a dummy module so `import` succeeds
        #   False -> mark it unavailable so `import` raises ImportError
        #   None  -> leave the real (installed or not) state untouched
        targets = {"talyn": talyn, "uvloop": uvloop, "winloop": winloop}
        saved = {}
        for name, state in targets.items():
            if name in sys.modules:
                saved[name] = sys.modules[name]
            if state is True:
                sys.modules[name] = types.ModuleType(name)
            elif state is False:
                sys.modules[name] = None
        try:
            with (
                patch.object(sys, "platform", platform_name),
                patch.object(sys, "version_info", version),
                patch("platform.machine", return_value=machine),
            ):
                yield proxy_module.select_event_loop()
        finally:
            for name in targets:
                if name in saved:
                    sys.modules[name] = saved[name]
                else:
                    sys.modules.pop(name, None)

    def test_linux_x86_64_py314_selects_talyn(self):
        """Linux x86_64 + CPython 3.13/3.14 -> Talyn is selected."""
        with self._patched_selection(
            "linux", "x86_64", (3, 14, 0, "final", 0), talyn=True
        ) as uv:
            assert uv is not None
            assert uv.__name__ == "talyn"

    def test_linux_talyn_import_fails_falls_back_to_uvloop(self):
        """Talyn import failure falls back to uvloop."""
        with self._patched_selection(
            "linux", "x86_64", (3, 14, 0, "final", 0), talyn=False, uvloop=True
        ) as uv:
            assert uv is not None
            assert uv.__name__ == "uvloop"

    def test_linux_riscv64_py314_selects_talyn(self):
        """Linux riscv64 + CPython 3.13/3.14 -> Talyn is selected."""
        with self._patched_selection(
            "linux", "riscv64", (3, 14, 0, "final", 0), talyn=True
        ) as uv:
            assert uv is not None
            assert uv.__name__ == "talyn"

    def test_linux_unsupported_arch_skips_talyn(self):
        """Linux on an unsupported arch (e.g. ppc64le) skips Talyn and uses uvloop."""
        with self._patched_selection(
            "linux", "ppc64le", (3, 14, 0, "final", 0), uvloop=True
        ) as uv:
            assert uv is not None
            assert uv.__name__ == "uvloop"

    def test_linux_wrong_python_version_skips_talyn(self):
        """Linux on CPython < 3.13 or > 3.14 skips Talyn and uses uvloop."""
        with self._patched_selection(
            "linux", "x86_64", (3, 12, 0, "final", 0), uvloop=True
        ) as uv:
            assert uv is not None
            assert uv.__name__ == "uvloop"

    def test_windows_selects_winloop(self):
        """Windows selects Winloop (no arch/version guards)."""
        with self._patched_selection(
            "win32", "AMD64", (3, 14, 0, "final", 0), winloop=True
        ) as uv:
            assert uv is not None
            assert uv.__name__ == "winloop"

    def test_windows_winloop_import_fails_falls_back_to_none(self):
        """Winloop import failure on Windows falls back to stdlib asyncio."""
        with self._patched_selection(
            "win32", "AMD64", (3, 14, 0, "final", 0), winloop=False
        ) as uv:
            assert uv is None

    def test_other_platform_uses_uvloop(self):
        """Non-Linux, non-Windows platforms use uvloop."""
        with self._patched_selection(
            "darwin", "x86_64", (3, 14, 0, "final", 0), uvloop=True
        ) as uv:
            assert uv is not None
            assert uv.__name__ == "uvloop"

    def test_all_loops_unavailable_falls_back_to_none(self):
        """If every fast loop is unavailable, select_event_loop returns None."""
        with self._patched_selection(
            "linux", "x86_64", (3, 14, 0, "final", 0), talyn=False, uvloop=False
        ) as uv:
            assert uv is None

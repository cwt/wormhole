#!/usr/bin/env python3
"""
Unit tests for the proxy module.
"""
import pytest
import sys
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from argparse import Namespace
from wormhole.proxy import main, main_async


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
            syslog_port=514
        )
        
        # Mock all the dependencies
        with patch('wormhole.proxy.uvloop') as mock_uvloop, \
             patch('wormhole.proxy.logger') as mock_logger, \
             patch('wormhole.proxy.resolver') as mock_resolver, \
             patch('wormhole.proxy.load_allowlist') as mock_load_allowlist, \
             patch('wormhole.proxy.load_ad_block_db') as mock_load_ad_block_db, \
             patch('wormhole.proxy.start_wormhole_server') as mock_start_server, \
             patch('wormhole.proxy.asyncio.Event') as mock_event, \
             patch('wormhole.proxy.asyncio.get_running_loop') as mock_get_loop:
            
            # Set up mocks
            mock_server = AsyncMock()
            mock_start_server.return_value = mock_server
            
            mock_shutdown_event = Mock()
            mock_event.return_value = mock_shutdown_event
            mock_shutdown_event.wait = AsyncMock()
            
            mock_loop = Mock()
            mock_get_loop.return_value = mock_loop
            
            # Mock uvloop.__name__ attribute
            mock_uvloop.__name__ = "uvloop"
            
            # Call the function
            await main_async(args)
            
            # Verify the calls
            mock_resolver.initialize.assert_called_once_with(verbose=0)
            mock_start_server.assert_called_once_with(
                "127.0.0.1", 8080, None, 0, False
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
            syslog_port=514
        )
        
        # Mock all the dependencies
        with patch('wormhole.proxy.uvloop') as mock_uvloop, \
             patch('wormhole.proxy.logger') as mock_logger, \
             patch('wormhole.proxy.resolver') as mock_resolver, \
             patch('wormhole.proxy.load_allowlist') as mock_load_allowlist, \
             patch('wormhole.proxy.load_ad_block_db') as mock_load_ad_block_db, \
             patch('wormhole.proxy.start_wormhole_server') as mock_start_server, \
             patch('wormhole.proxy.asyncio.Event') as mock_event, \
             patch('wormhole.proxy.asyncio.get_running_loop') as mock_get_loop:
            
            # Set up mocks
            mock_load_allowlist.return_value = 10
            
            mock_server = AsyncMock()
            mock_start_server.return_value = mock_server
            
            mock_shutdown_event = Mock()
            mock_event.return_value = mock_shutdown_event
            mock_shutdown_event.wait = AsyncMock()
            
            mock_loop = Mock()
            mock_get_loop.return_value = mock_loop
            
            # Mock uvloop.__name__ attribute
            mock_uvloop.__name__ = "uvloop"
            
            # Call the function
            await main_async(args)
            
            # Verify the calls
            mock_load_allowlist.assert_called_once()
            mock_start_server.assert_called_once()

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
            syslog_port=514
        )
        
        # Mock all the dependencies
        with patch('wormhole.proxy.uvloop') as mock_uvloop, \
             patch('wormhole.proxy.logger') as mock_logger, \
             patch('wormhole.proxy.resolver') as mock_resolver, \
             patch('wormhole.proxy.load_allowlist') as mock_load_allowlist, \
             patch('wormhole.proxy.load_ad_block_db') as mock_load_ad_block_db, \
             patch('wormhole.proxy.start_wormhole_server') as mock_start_server, \
             patch('wormhole.proxy.asyncio.Event') as mock_event, \
             patch('wormhole.proxy.asyncio.get_running_loop') as mock_get_loop:
            
            # Set up mocks
            mock_load_ad_block_db.return_value = 100
            
            mock_server = AsyncMock()
            mock_start_server.return_value = mock_server
            
            mock_shutdown_event = Mock()
            mock_event.return_value = mock_shutdown_event
            mock_shutdown_event.wait = AsyncMock()
            
            mock_loop = Mock()
            mock_get_loop.return_value = mock_loop
            
            # Mock uvloop.__name__ attribute
            mock_uvloop.__name__ = "uvloop"
            
            # Call the function
            await main_async(args)
            
            # Verify the calls
            mock_load_ad_block_db.assert_called_once()
            mock_start_server.assert_called_once()


class TestMain:
    """Test cases for the main function."""

    def test_main_license(self):
        """Test main with --license argument."""
        test_args = ["wormhole", "--license"]
        
        with patch.object(sys, 'argv', test_args):
            with patch('wormhole.proxy.ArgumentParser.parse_args') as mock_parse, \
                 patch('wormhole.proxy.Path') as mock_path, \
                 patch('builtins.print') as mock_print:
                
                mock_args = Mock()
                mock_args.license = True
                mock_args.auth_add = None
                mock_args.auth_mod = None
                mock_args.auth_del = None
                mock_args.update_ad_block_db = None
                mock_parse.return_value = mock_args
                
                # Mock Path properly
                mock_path_instance = MagicMock()
                mock_path_instance.__truediv__ = lambda self, other: MagicMock()
                mock_path_instance.read_text.return_value = "License text"
                mock_path.return_value = mock_path_instance
                
                result = main()
                assert result == 0

    def test_main_auth_add(self):
        """Test main with --auth-add argument."""
        test_args = ["wormhole", "--auth-add", "/path/to/auth", "username"]
        
        with patch.object(sys, 'argv', test_args):
            with patch('wormhole.proxy.ArgumentParser.parse_args') as mock_parse, \
                 patch('wormhole.proxy.add_user') as mock_add_user:
                
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
                mock_add_user.assert_called_once_with("/path/to/auth", "username")

    def test_main_auth_mod(self):
        """Test main with --auth-mod argument."""
        test_args = ["wormhole", "--auth-mod", "/path/to/auth", "username"]
        
        with patch.object(sys, 'argv', test_args):
            with patch('wormhole.proxy.ArgumentParser.parse_args') as mock_parse, \
                 patch('wormhole.proxy.modify_user') as mock_modify_user:
                
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
                mock_modify_user.assert_called_once_with("/path/to/auth", "username")

    def test_main_auth_del(self):
        """Test main with --auth-del argument."""
        test_args = ["wormhole", "--auth-del", "/path/to/auth", "username"]
        
        with patch.object(sys, 'argv', test_args):
            with patch('wormhole.proxy.ArgumentParser.parse_args') as mock_parse, \
                 patch('wormhole.proxy.delete_user') as mock_delete_user:
                
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
                mock_delete_user.assert_called_once_with("/path/to/auth", "username")

    def test_main_update_ad_block_db(self):
        """Test main with --update-ad-block-db argument."""
        test_args = ["wormhole", "--update-ad-block-db", "/path/to/adblock.db"]
        
        with patch.object(sys, 'argv', test_args):
            with patch('wormhole.proxy.ArgumentParser.parse_args') as mock_parse, \
                 patch('wormhole.proxy.setup_logger') as mock_setup_logger, \
                 patch('wormhole.proxy.update_database') as mock_update_db, \
                 patch('wormhole.proxy.asyncio.run') as mock_asyncio_run:
                
                mock_args = Mock()
                mock_args.license = False
                mock_args.auth_add = None
                mock_args.auth_mod = None
                mock_args.auth_del = None
                mock_args.update_ad_block_db = "/path/to/adblock.db"
                mock_args.allowlist = None
                mock_args.syslog_host = None
                mock_args.syslog_port = 514
                mock_args.verbose = 0
                mock_args.auth = None  # Add the auth attribute
                mock_parse.return_value = mock_args
                
                mock_asyncio_run.return_value = None
                
                # Mock the event loop to avoid RuntimeError
                with patch('asyncio.get_event_loop') as mock_get_loop:
                    mock_loop = Mock()
                    mock_get_loop.return_value = mock_loop
                    mock_loop.is_running.return_value = False
                    
                    result = main()
                    assert result == 0
                    mock_setup_logger.assert_called_once_with(None, 514, 0, async_mode=False)
                    mock_asyncio_run.assert_called_once()

    def test_main_server_mode(self):
        """Test main in server mode."""
        test_args = ["wormhole"]
        
        with patch.object(sys, 'argv', test_args):
            with patch('wormhole.proxy.ArgumentParser.parse_args') as mock_parse, \
                 patch('wormhole.proxy.uvloop') as mock_uvloop, \
                 patch('wormhole.proxy.setup_logger') as mock_setup_logger, \
                 patch('wormhole.proxy.asyncio.run') as mock_asyncio_run:
                
                # Mock uvloop to not have the 'run' attribute, so it will use asyncio.run
                del mock_uvloop.run
                
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
                mock_parse.return_value = mock_args
                
                # Mock asyncio.run to avoid actually running the async function
                mock_asyncio_run.return_value = None
                
                # Mock the event loop to avoid RuntimeError
                with patch('asyncio.get_event_loop') as mock_get_loop:
                    mock_loop = Mock()
                    mock_get_loop.return_value = mock_loop
                    mock_loop.is_running.return_value = False
                    
                    result = main()
                    assert result == 0
                    mock_setup_logger.assert_called_once_with(None, 514, 0, async_mode=True)
                    mock_asyncio_run.assert_called_once()

    def test_main_invalid_port(self):
        """Test main with invalid port."""
        test_args = ["wormhole", "--port", "100"]
        
        with patch.object(sys, 'argv', test_args):
            with patch('wormhole.proxy.ArgumentParser.parse_args') as mock_parse:
                
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
                
                # This should cause the parser to call sys.exit
                with patch('sys.exit') as mock_exit:
                    main()
                    mock_exit.assert_called_once()
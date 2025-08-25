#!/usr/bin/env python3
"""
Unit tests for the logger module.
"""
import pytest
import asyncio
from unittest.mock import Mock, patch, MagicMock
from wormhole.logger import LogThrottler, setup_logger, format_log_message


class TestLogThrottler:
    """Test cases for the LogThrottler class."""

    @pytest.mark.asyncio
    async def test_log_throttler_new_message(self):
        """Test that a new message is logged immediately."""
        mock_logger = Mock()
        throttler = LogThrottler(mock_logger, "info")

        # Test logging a new message
        throttler.process("Test message")

        # Verify the message was logged
        mock_logger.opt().log.assert_called_once_with("INFO", "Test message")

    @pytest.mark.asyncio
    async def test_log_throttler_repeated_message(self):
        """Test that repeated messages are throttled."""
        mock_logger = Mock()
        throttler = LogThrottler(
            mock_logger, "info", delay=0.1
        )  # Short delay for testing

        # Log the same message twice
        throttler.process("Repeated message")
        throttler.process("Repeated message")

        # First call should log immediately
        mock_logger.opt().log.assert_called_once_with(
            "INFO", "Repeated message"
        )

        # Wait for the delay to expire
        await asyncio.sleep(0.15)

        # Second call should have been counted as a repeat
        # The summary should be logged when the timer expires

    @pytest.mark.asyncio
    async def test_log_throttler_different_messages(self):
        """Test that different messages are all logged."""
        mock_logger = Mock()
        throttler = LogThrottler(mock_logger, "info", delay=0.1)

        # Log two different messages
        throttler.process("First message")
        throttler.process("Second message")

        # Both messages should be logged
        assert mock_logger.opt().log.call_count == 2
        mock_logger.opt().log.assert_any_call("INFO", "First message")
        mock_logger.opt().log.assert_any_call("INFO", "Second message")

    @pytest.mark.asyncio
    async def test_log_throttler_summary_multiple_repeats(self):
        """Test that repeated messages show a summary."""
        mock_logger = Mock()
        throttler = LogThrottler(mock_logger, "info", delay=0.1)

        # Log the same message multiple times
        throttler.process("Repeated message")
        throttler.process("Repeated message")
        throttler.process("Repeated message")

        # Wait for the delay to expire
        await asyncio.sleep(0.15)

        # The summary should be logged


class TestSetupLogger:
    """Test cases for the setup_logger function."""

    def test_setup_logger_basic(self):
        """Test basic logger setup."""
        with (
            patch("wormhole.logger.logger.remove"),
            patch("wormhole.logger.logger.add"),
            patch("wormhole.logger.logging.getLogger"),
        ):
            setup_logger()

    def test_setup_logger_verbose(self):
        """Test logger setup with verbose mode."""
        with (
            patch("wormhole.logger.logger.remove"),
            patch("wormhole.logger.logger.add"),
            patch("wormhole.logger.logging.getLogger"),
        ):
            setup_logger(verbose=1)

    def test_setup_logger_very_verbose(self):
        """Test logger setup with very verbose mode."""
        with (
            patch("wormhole.logger.logger.remove"),
            patch("wormhole.logger.logger.add"),
            patch("wormhole.logger.logging.getLogger"),
        ):
            setup_logger(verbose=2)

    def test_setup_logger_syslog(self):
        """Test logger setup with syslog."""
        with (
            patch("wormhole.logger.logger.remove"),
            patch("wormhole.logger.logger.add"),
            patch("wormhole.logger.logging.getLogger"),
            patch("wormhole.logger.logging.handlers.SysLogHandler"),
            patch("wormhole.logger.os.path.exists", return_value=True),
        ):
            setup_logger(syslog_host="/dev/log")

    def test_setup_logger_syslog_network(self):
        """Test logger setup with network syslog."""
        with (
            patch("wormhole.logger.logger.remove"),
            patch("wormhole.logger.logger.add"),
            patch("wormhole.logger.logging.getLogger"),
            patch("wormhole.logger.logging.handlers.SysLogHandler"),
            patch("wormhole.logger.os.uname") as mock_uname,
        ):
            mock_uname.return_value.nodename = "testhost"
            setup_logger(syslog_host="syslog.example.com")


class TestFormatLogMessage:
    """Test cases for the format_log_message function."""

    def test_format_log_message_normal(self):
        """Test formatting a log message with normal verbosity."""
        message = "Test log message"
        ident = {"id": "123456", "client": "192.168.1.1"}
        result = format_log_message(message, ident, 0)
        assert result == "[192.168.1.1]: Test log message"

    def test_format_log_message_verbose(self):
        """Test formatting a log message with verbose mode."""
        message = "Test log message"
        ident = {"id": "123456", "client": "192.168.1.1"}
        result = format_log_message(message, ident, 2)
        assert result == "[123456][192.168.1.1]: Test log message"

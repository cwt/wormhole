# Wormhole Tests

This directory contains the unit tests for the Wormhole proxy project.

## Running Tests

To run all tests:

```bash
python -m pytest tests/
```

To run tests with verbose output:

```bash
python -m pytest tests/ -v
```

To run tests with coverage:

```bash
python -m pytest tests/ --cov=wormhole
```

## Test Structure

- `test_context.py` - Tests for the RequestContext class
- `test_context_integration.py` - Integration tests for RequestContext usage
- `test_handler.py` - Tests for the handler module functions
- `test_safeguards.py` - Tests for the safeguards module functions
- `test_tools.py` - Tests for the tools module functions

## Dependencies

The tests require the following dependencies which are included in the dev dependencies:

- pytest
- pytest-asyncio
- pytest-cov
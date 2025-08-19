#!/bin/bash

rm -rf */__pycache__ .pytest_cache
poetry update
poetry install
poetry run pytest --cov=wormhole --cov-report=term-missing

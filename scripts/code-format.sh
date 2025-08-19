#!/bin/bash

poetry run black -t py312 -l 80 wormhole/*.py
poetry run black -t py312 -l 80 tests/*.py

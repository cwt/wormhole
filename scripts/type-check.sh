#!/bin/bash

# Ignore missing stubs for optional dependencies (uvloop, winloop)
mypy --ignore-missing-imports .

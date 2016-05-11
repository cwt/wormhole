#!/bin/bash

pandoc -f rst -t markdown_github --columns=79 README.rst > README.md

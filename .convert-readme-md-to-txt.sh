#!/bin/bash

pandoc -f markdown_github -t plain --columns=79 README.md > README.txt

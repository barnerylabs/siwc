#!/bin/sh
# A keychain tool that accepts every command: it reads its standard input to
# the end, so a write to it cannot fail with a broken pipe.
exec cat > /dev/null

#!/bin/sh
[ "$1" = lookup ] || exit 2
exec "$SIWC_TEST_KEYCHAIN_LOOKUP_EXE" --exact responses::key_lock::the_keychain_helper_for_the_lookup_test

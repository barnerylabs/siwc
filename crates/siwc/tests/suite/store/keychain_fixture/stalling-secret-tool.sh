#!/bin/sh
dir=${0%/*}
case "$1" in
    store)
        IFS= read -r key || [ -n "$key" ] || exit 2
        printf '%s\n' "$key" > "$dir/item"
        printf 'store\n' >> "$dir/writes"
        ;;
    lookup) ;;
    search)
        # Lists nothing for an absent item, as the real tool does.
        [ ! -f "$dir/item" ] || printf '[/1]\nlabel = item\n'
        exit 0
        ;;
    *) exit 2 ;;
esac
if [ -f "$dir/stall" ]; then
    IFS= read -r stall < "$dir/stall"
    if [ "$1" = "$stall" ]; then
        IFS= read -r runner < "$dir/runner"
        export SIWC_TEST_KEYCHAIN_HELPER_DEADLINE_GATE="$dir/gate"
        exec "$runner" --exact store::keychain::helper::deadline_tests::the_stalled_keychain_helper
    fi
fi
if [ "$1" = lookup ]; then
    [ -f "$dir/item" ] || exit 1
    IFS= read -r key < "$dir/item"
    printf '%s\n' "$key"
fi

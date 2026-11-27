#!/bin/sh
dir=${0%/*}

pause() {
    if [ -p "$dir/pause-$1" ]; then
        : > "$dir/$1-started"
        IFS= read -r _ < "$dir/pause-$1" || exit 2
        /bin/rm "$dir/pause-$1" || exit 2
    fi
}

case "$1" in
    lookup)
        pause lookup
        pause "lookup-$3"
        [ ! -e "$dir/locked" ] && [ ! -e "$dir/$3.missing" ] && [ -f "$dir/$3" ] || exit 1
        [ ! -e "$dir/$3.fail-readback" ] || exit 2
        IFS= read -r key < "$dir/$3"
        if [ -e "$dir/$3.forget" ]; then
            /bin/rm "$dir/$3" || exit 2
        fi
        printf '%s\n' "$key"
        ;;
    search)
        # `search --all service S account A`, answered as the real tool does:
        # nothing for an absent item, the item without its secret and a
        # complaint on stderr while the collection is locked.
        [ "$2" = --all ] || exit 2
        [ ! -e "$dir/$4.fail-search" ] || exit 2
        [ ! -e "$dir/$4.missing" ] && [ -f "$dir/$4" ] || exit 0
        printf '[/1]\nlabel = %s\n' "$4"
        if [ -e "$dir/locked" ]; then
            printf 'secret-tool: Cannot get secret of a locked object\n' >&2
        else
            IFS= read -r key < "$dir/$4"
            printf 'secret = %s\n' "$key"
        fi
        ;;
    store)
        pause "store-$5"
        [ ! -e "$dir/$5.fail-store" ] || exit 2
        if [ -e "$dir/$5.forget" ]; then
            # Stop an unbounded client without waiting for a test timeout.
            attempts=0
            [ ! -f "$dir/attempts" ] || IFS= read -r attempts < "$dir/attempts"
            attempts=$((attempts + 1))
            printf '%s\n' "$attempts" > "$dir/attempts"
            [ "$attempts" -le 6 ] || exit 2
        fi
        IFS= read -r key || [ -n "$key" ] || exit 2
        printf '%s\n' "$key" > "$dir/$5"
        printf '%s\n' "$5" >> "$dir/writes"
        /bin/rm -f "$dir/locked"
        ;;
    *) exit 2 ;;
esac

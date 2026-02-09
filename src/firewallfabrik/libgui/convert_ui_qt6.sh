#!/bin/bash
# Opens each .ui file in pyside6-designer, saves it (Ctrl+S), and closes (Ctrl+Q).
# This effectively converts the files to Qt6 format.

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

DESIGNER="pyside6-designer"
TOTAL=$(ls -1 *.ui 2>/dev/null | wc -l)
COUNT=0
FAILED=()

for f in *.ui; do
    COUNT=$((COUNT + 1))
    echo "[$COUNT/$TOTAL] Processing: $f"

    # Open designer with the file
    "$DESIGNER" "$f" &
    PID=$!

    # Wait for a window from this process to appear
    WID=""
    for i in $(seq 1 20); do
        WID=$(xdotool search --pid "$PID" 2>/dev/null | tail -1)
        if [ -n "$WID" ]; then
            break
        fi
        sleep 0.5
    done

    if [ -z "$WID" ]; then
        echo "  WARNING: Could not find window for $f after 10s"
        FAILED+=("$f")
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
        continue
    fi

    # Give the form time to fully load
    sleep 1

    # Re-check window (sometimes the initial window changes)
    WID=$(xdotool search --pid "$PID" 2>/dev/null | tail -1)

    # Activate and focus the window
    xdotool windowactivate --sync "$WID" 2>/dev/null || true
    xdotool windowfocus --sync "$WID" 2>/dev/null || true
    sleep 0.3

    # Save with Ctrl+S
    xdotool key --clearmodifiers ctrl+s
    sleep 0.5

    # Close with Ctrl+Q
    xdotool key --clearmodifiers ctrl+q
    sleep 0.5

    # Wait for process to exit (with timeout)
    for i in $(seq 1 10); do
        if ! kill -0 "$PID" 2>/dev/null; then
            break
        fi
        sleep 0.5
    done

    # Force kill if still running
    if kill -0 "$PID" 2>/dev/null; then
        echo "  WARNING: Designer did not exit cleanly for $f, force killing"
        kill "$PID" 2>/dev/null || true
    fi

    wait "$PID" 2>/dev/null || true
    echo "  Done: $f"
done

echo ""
echo "=============================="
echo "Processed $COUNT files."
if [ ${#FAILED[@]} -gt 0 ]; then
    echo "Failed files (${#FAILED[@]}):"
    for f in "${FAILED[@]}"; do
        echo "  - $f"
    done
else
    echo "All files processed successfully."
fi

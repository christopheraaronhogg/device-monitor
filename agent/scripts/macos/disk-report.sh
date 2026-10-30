#!/bin/bash
# desc: Disk report: free space and the largest folders in the home folder
df -h 2>/dev/null | grep -v -E 'tmpfs|devfs|map '
echo; echo "== Largest folders in $HOME"
du -xhd1 "$HOME" 2>/dev/null | sort -hr | head -15

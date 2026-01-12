#!/bin/bash
# Setup script for tau2 scenario
# This downloads the tau2-bench data required to run the benchmark

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAU2_BENCH_DIR="$SCRIPT_DIR/tau2-bench"

if [ -d "$TAU2_BENCH_DIR" ]; then
    echo "tau2-bench already exists at $TAU2_BENCH_DIR"
    echo "To re-download, remove the directory first: rm -rf $TAU2_BENCH_DIR"
    exit 0
fi

echo "Cloning tau2-bench repository..."
git clone --depth 1 https://github.com/sierra-research/tau2-bench.git "$TAU2_BENCH_DIR"

echo ""
echo "Setup complete! tau2-bench data is now available at:"
echo "  $TAU2_BENCH_DIR/data"
echo ""
echo "To run the tau2 scenario:"
echo "  uv run agentbeats-run scenarios/tau2/scenario.toml"
echo ""
echo "To use a different data directory:"
echo "  TAU2_DATA_DIR=/path/to/tau2-bench/data uv run agentbeats-run scenarios/tau2/scenario.toml"

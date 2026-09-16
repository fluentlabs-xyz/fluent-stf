#!/usr/bin/env python3
"""Rewrite the `EXPECTED_PCR0` constant (for a given network) in
nitro-validator `lib.rs` from PCR JSON produced by either `nitro-cli
build-enclave` (nested `Measurements.PCR0`) or monzo/aws-nitro-util's
buildEif (flat `PCR0`). Optionally also rewrites the matching
`<!-- pcr0:<network>:begin --> ... <!-- pcr0:<network>:end -->`
sentinel block inside a README.

Usage:
    update_expected_pcr0.py <pcr.json> <lib.rs> <network> [--readme <README.md>]

`network` must be one of: mainnet, testnet.
Only the `#[cfg(feature = "<network>")] pub const EXPECTED_PCR0 …` block is rewritten
in `lib.rs`. If `--readme` is supplied, the single
`<!-- pcr0:<network>:begin -->…<!-- pcr0:<network>:end -->` block is
rewritten with the same PCR0 value.
"""
import argparse
import json
import pathlib
import re
import sys

NETWORKS = ("mainnet", "testnet")


def patch_lib_rs(lib_rs: pathlib.Path, network: str, pcr0_hex: str) -> None:
    bytes_list = [f"0x{pcr0_hex[i : i + 2]}" for i in range(0, 96, 2)]
    rows = [
        "    " + ", ".join(bytes_list[row * 8 : (row + 1) * 8]) + ","
        for row in range(6)
    ]
    new_block = (
        f'#[cfg(feature = "{network}")]\n'
        "pub const EXPECTED_PCR0: [u8; 48] = [\n"
        + "\n".join(rows)
        + "\n];"
    )

    src = lib_rs.read_text()
    pattern = re.compile(
        r'#\[cfg\(feature = "' + re.escape(network) + r'"\)\]\s*\n'
        r"pub const EXPECTED_PCR0: \[u8; 48\] = \[[^\]]*\];",
        re.DOTALL,
    )
    new_src, n = pattern.subn(new_block, src)
    if n != 1:
        sys.exit(
            f"expected 1 EXPECTED_PCR0 block for feature `{network}` in {lib_rs}, "
            f"found {n}"
        )
    lib_rs.write_text(new_src)
    print(f"Updated EXPECTED_PCR0[{network}] in {lib_rs} → {pcr0_hex}")


def patch_readme(readme: pathlib.Path, network: str, pcr0_hex: str) -> None:
    src = readme.read_text()
    pattern = re.compile(
        r"<!-- pcr0:" + re.escape(network) + r":begin -->"
        r".*?"
        r"<!-- pcr0:" + re.escape(network) + r":end -->",
        re.DOTALL,
    )
    replacement = (
        f"<!-- pcr0:{network}:begin -->"
        f"`{pcr0_hex}`"
        f"<!-- pcr0:{network}:end -->"
    )
    new_src, n = pattern.subn(replacement, src)
    if n != 1:
        sys.exit(
            f"expected 1 pcr0:{network} sentinel block in {readme}, found {n}"
        )
    readme.write_text(new_src)
    print(f"Updated pcr0:{network} in {readme}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Patch EXPECTED_PCR0 in lib.rs (and optionally the identity-table sentinel in README)."
    )
    parser.add_argument("pcr_json", type=pathlib.Path)
    parser.add_argument("lib_rs", type=pathlib.Path)
    parser.add_argument("network", choices=NETWORKS)
    parser.add_argument(
        "--readme",
        type=pathlib.Path,
        default=None,
        help="Optional path to README whose pcr0:<network> sentinel block should also be rewritten.",
    )
    args = parser.parse_args()

    data = json.loads(args.pcr_json.read_text())
    if "Measurements" in data:
        pcr0_hex = data["Measurements"]["PCR0"]
    elif "PCR0" in data:
        pcr0_hex = data["PCR0"]
    else:
        sys.exit(
            f"no PCR0 key found in {args.pcr_json} (expected 'Measurements.PCR0' or 'PCR0')"
        )
    if len(pcr0_hex) != 96:
        sys.exit(f"expected 96 hex chars (48 bytes), got {len(pcr0_hex)}: {pcr0_hex!r}")
    pcr0_hex = pcr0_hex.lower()

    patch_lib_rs(args.lib_rs, args.network, pcr0_hex)
    if args.readme is not None:
        patch_readme(args.readme, args.network, pcr0_hex)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""Rewrite the per-network vkey cells and the global `version` cell in
the identity table of a README, from the SP1-verifier keys emitted by
`cargo prove vkey` during `build-client-docker` /
`build-nitro-validator-docker`.

Usage:
    update_readme_vkeys.py <rsp-client.vkey> <nitro-validator.vkey> <README.md> <network>

Pass `-` as <rsp-client.vkey> to leave the rsp-client cell untouched (release
built with SP1_CLIENT=0, i.e. without the SP1 client ELF).

Patches three sentinel blocks:
    <!-- rsp-vkey:<network>:begin -->`0x…`<!-- rsp-vkey:<network>:end -->
    <!-- nv-vkey:<network>:begin -->`0x…`<!-- nv-vkey:<network>:end -->
    <!-- version:begin -->`v<release>`<!-- version:end -->

The release version is read from `bin/client/Cargo.toml` and validated
against `bin/aws-nitro-validator/Cargo.toml` — they must match, since
the two artifacts are released together and their version is what the
README tags as the verifiable release.
"""
import pathlib
import re
import sys

NETWORKS = ("mainnet", "testnet")

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CLIENT_CARGO_TOML = REPO_ROOT / "bin" / "client" / "Cargo.toml"
NV_CARGO_TOML = REPO_ROOT / "bin" / "aws-nitro-validator" / "Cargo.toml"


def read_vkey(path: pathlib.Path) -> str:
    line = path.read_text().strip()
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", line):
        sys.exit(f"{path}: not a 0x-prefixed 32-byte hex string (got {line!r})")
    return line.lower()


def read_package_version(cargo_toml: pathlib.Path) -> str:
    """Extract `version = "X.Y.Z"` from the first [package] section."""
    src = cargo_toml.read_text()
    match = re.search(
        r"^\[package\][^\[]*?^\s*version\s*=\s*\"([^\"]+)\"",
        src,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        sys.exit(f"could not find [package].version in {cargo_toml}")
    return match.group(1)


def read_release_version() -> str:
    client_ver = read_package_version(CLIENT_CARGO_TOML)
    nv_ver = read_package_version(NV_CARGO_TOML)
    if client_ver != nv_ver:
        sys.exit(
            f"version mismatch: {CLIENT_CARGO_TOML} has {client_ver!r}, "
            f"{NV_CARGO_TOML} has {nv_ver!r} — bump both before running"
        )
    return client_ver


def patch_sentinel(src: str, tag: str, value: str) -> str:
    pattern = re.compile(
        r"<!-- " + re.escape(tag) + r":begin -->"
        r".*?"
        r"<!-- " + re.escape(tag) + r":end -->",
        re.DOTALL,
    )
    replacement = f"<!-- {tag}:begin -->`{value}`<!-- {tag}:end -->"
    new_src, n = pattern.subn(replacement, src)
    if n != 1:
        sys.exit(f"expected exactly 1 `{tag}` sentinel block, found {n}")
    return new_src


def main() -> None:
    if len(sys.argv) != 5:
        sys.exit(
            "usage: update_readme_vkeys.py <rsp.vkey> <nv.vkey> <README.md> <network>"
        )
    rsp_vkey_path = pathlib.Path(sys.argv[1])
    nv_vkey_path = pathlib.Path(sys.argv[2])
    readme = pathlib.Path(sys.argv[3])
    network = sys.argv[4]

    if network not in NETWORKS:
        sys.exit(f"network must be one of {NETWORKS}, got {network!r}")

    rsp_vkey = None if str(rsp_vkey_path) == "-" else read_vkey(rsp_vkey_path)
    nv_vkey = read_vkey(nv_vkey_path)
    version = f"v{read_release_version()}"

    src = readme.read_text()
    if rsp_vkey is not None:
        src = patch_sentinel(src, f"rsp-vkey:{network}", rsp_vkey)
    src = patch_sentinel(src, f"nv-vkey:{network}", nv_vkey)
    src = patch_sentinel(src, "version", version)
    readme.write_text(src)
    print(f"Updated vkeys[{network}] + version ({version}) in {readme}")


if __name__ == "__main__":
    main()

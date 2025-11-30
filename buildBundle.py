#!/usr/bin/env python3
"""
Build an artifact bundle for Apache Pulsar C++ client by downloading
prebuilt packages for macOS and Linux (arm64/x64), assembling the
`libpulsar.artifactbundle` layout and zipping the result.

Usage:
  python buildBundle.py [--version VERSION] [--outdir OUTDIR] [--keep-temp]

The script will try common filename patterns on the official Apache
downloads (`downloads.apache.org`) and the archive mirror. If a
platform's prebuilt cannot be found the script will skip it and
continue with others.

It expects the repository layout where `resources/LICENSES` contains
license files that should be copied into the bundle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tarfile
import zipfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Dict, List, Tuple

from config import DEFAULT_VERSION, PLATFORMS, DOWNLOAD_BASES


def log(msg: str) -> None:
    print(msg)


def download_file(url: str, dest: Path) -> bool:
    try:
        log(f"Downloading {url}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url) as r, open(dest, "wb") as f:
            shutil.copyfileobj(r, f)
        return True
    except Exception as e:
        log(f"  -> failed: {e}")
        return False


def verify_checksum(file_path: Path, checksum_url: str) -> bool:
    """Verify SHA512 checksum of a file against a remote checksum file."""
    try:
        log(f"Downloading checksum from {checksum_url}")
        with urllib.request.urlopen(checksum_url) as r:
            checksum_content = r.read().decode('utf-8').strip()
        
        # Parse the checksum file (format: "hash  filename" or just "hash")
        expected_hash = checksum_content.split()[0].lower()
        
        log(f"Calculating SHA512 checksum for {file_path.name}")
        sha512 = hashlib.sha512()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha512.update(chunk)
        actual_hash = sha512.hexdigest().lower()
        
        if actual_hash == expected_hash:
            log(f"  ✓ Checksum verified")
            return True
        else:
            log(f"  ✗ Checksum mismatch!")
            log(f"    Expected: {expected_hash}")
            log(f"    Got:      {actual_hash}")
            return False
    except Exception as e:
        log(f"  -> checksum verification failed: {e}")
        return False


def try_find_and_download(version: str, candidates: List[str], workdir: Path, platform_key: str) -> Tuple[Path, str] | None:
    for base in DOWNLOAD_BASES:
        base_filled = base.format(v=version)
        for cand in candidates:
            fname = cand.format(v=version)
            url = base_filled + fname
            checksum_url = url + ".sha512"
            
            # Use platform key to create unique filenames
            unique_fname = fname.replace("/", "_")
            if not unique_fname.startswith(platform_key):
                unique_fname = f"{platform_key}_{unique_fname}"
            dest = workdir / unique_fname
            
            if download_file(url, dest):
                # Verify checksum
                if verify_checksum(dest, checksum_url):
                    return dest, url
                else:
                    log(f"  -> Checksum verification failed, skipping this file")
                    dest.unlink()  # Remove the file with bad checksum
    return None


def extract_archive(archive_path: Path, dest: Path) -> None:
    """Extract either a tar.gz or a zip archive to dest."""
    log(f"Extracting {archive_path} -> {dest}")
    if archive_path.suffix == ".zip":
        with zipfile.ZipFile(archive_path, "r") as z:
            z.extractall(dest)
    else:
        with tarfile.open(archive_path, "r:gz") as t:
            t.extractall(dest)


def find_include_and_libs(extract_root: Path) -> Tuple[Path | None, List[Path]]:
    include = None
    libs: List[Path] = []
    
    # Look for include/pulsar or usr/include/pulsar
    for p in extract_root.rglob("pulsar"):
        if p.is_dir() and p.parent.name == "include":
            include = p.parent
            break
    
    # Fallback: look for any include directory
    if not include:
        for p in extract_root.rglob("include"):
            if p.is_dir():
                include = p
                break

    # Look for lib directories (lib or usr/lib)
    for p in extract_root.rglob("lib"):
        if p.is_dir():
            for f in p.iterdir():
                if f.suffix in (".a", ".dylib", ".so", ".lib"):
                    libs.append(f)

    return include, libs


def assemble_bundle(found: Dict[str, Dict], version: str, outdir: Path, keep_temp: bool) -> Path:
    bundle_root = outdir / f"libpulsar.artifactbundle"
    if bundle_root.exists():
        shutil.rmtree(bundle_root)
    bundle_root.mkdir(parents=True)

    resources_licenses = Path("resources") / "LICENSES"
    dest_licenses = bundle_root / "LICENSES"
    dest_licenses.mkdir()
    if resources_licenses.exists():
        for f in resources_licenses.iterdir():
            shutil.copy2(f, dest_licenses / f.name)

    include_written = False
    for plat, info in found.items():
        inc = info.get("include")
        if inc and inc.exists() and not include_written:
            shutil.copytree(inc, bundle_root / "include")
            include_written = True

    modulemap_path = bundle_root / "include" / "libpulsar.modulemap"
    if (bundle_root / "include").exists():
        pulsar_include_dir = bundle_root / "include" / "pulsar"
        if pulsar_include_dir.exists() and pulsar_include_dir.is_dir():
            headers = []
            for p in sorted(pulsar_include_dir.rglob("*.h")):
                rel = p.relative_to(bundle_root / "include")
                headers.append(str(rel).replace("\\", "/"))

            if headers:
                log(f"Writing modulemap with {len(headers)} headers to {modulemap_path}")
                with open(modulemap_path, "w", encoding="utf-8") as mm:
                    mm.write("module CxxPulsar {\n")
                    for h in headers:
                        if not h.startswith("pulsar/c") and not h=="pulsar/ProtobufNativeSchema.h":
                            mm.write(f"    header \"{h}\"\n")
                    mm.write("    export *\n")
                    mm.write("}\n")

    variants = []
    dist_root = bundle_root / "dist"
    for plat, info in found.items():
        libs = info.get("libs", [])
        if not libs:
            continue
        plat_dir = dist_root / plat
        plat_dir.mkdir(parents=True, exist_ok=True)
        chosen = None
        for f in libs:
            if f.name.endswith("withdeps.a") or f.name == "pulsarWithDeps.lib":
                chosen = f
                break
        if chosen is None:
            for f in libs:
                if f.suffix == ".a" or (f.suffix == ".lib" and "static" in f.name.lower()):
                    chosen = f
                    break
        if chosen is None:
            chosen = libs[0]

        target_name = chosen.name
        if chosen.name == "pulsarWithDeps.lib":
            target_name = "libpulsarwithdeps.lib"
        shutil.copy2(chosen, plat_dir / target_name)

        variant = {
            "path": str((Path("dist") / plat / target_name).as_posix()),
            "supportedTriples": info.get("triples", []),
            "staticLibraryMetadata": {"headerPaths": ["include"]},
        }
        if (bundle_root / "include" / "libpulsar.modulemap").exists():
            variant["staticLibraryMetadata"]["moduleMapPath"] = "include/libpulsar.modulemap"
        variants.append(variant)

    info = {
        "schemaVersion": "1.0",
        "artifacts": {
            "CxxPulsar": {
                "type": "staticLibrary",
                "version": version,
                "variants": variants,
            }
        },
    }

    with open(bundle_root / "info.json", "w", encoding="utf-8") as f:
        json.dump(info, f, indent=4)

    zip_name = outdir / f"libpulsar.artifactbundle.zip"
    log(f"Creating zip {zip_name}")
    shutil.make_archive(str(zip_name.with_suffix("")), "zip", root_dir=bundle_root)

    if not keep_temp:
        pass

    return zip_name


def main(argv: List[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--version", help="Pulsar client-cpp version (e.g. 3.7.2)")
    p.add_argument("--outdir", default=".", help="Output directory for artifact bundle zip")
    p.add_argument("--keep-temp", action="store_true", help="Keep temporary download/extract directory")
    args = p.parse_args(argv)

    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    version = args.version
    if not version:
        version = DEFAULT_VERSION
        log(f"Using default version {version}")

    workdir = Path(tempfile.mkdtemp(prefix="pulsar-cpp-bundle-"))
    log(f"Working in {workdir}")

    found: Dict[str, Dict] = {}
    try:
        for plat_key, plat_info in PLATFORMS.items():
            res = try_find_and_download(version, plat_info["candidates"], workdir, plat_key)
            if not res:
                log(f"No prebuilt found for {plat_key}, skipping")
                continue
            archive_path, url = res
            extract_dir = workdir / (archive_path.stem + "_ex")
            extract_dir.mkdir()
            extract_archive(archive_path, extract_dir)
            include, libs = find_include_and_libs(extract_dir)
            libs = [p.resolve() for p in libs]
            found[plat_key] = {"include": include, "libs": libs, "triples": plat_info["triples"]}

        if not found:
            log("ERROR: no prebuilt packages found for any platform")
            return 3

        zip_path = assemble_bundle(found, version, outdir, args.keep_temp)
        log(f"Bundle created: {zip_path}")

        return 0
    finally:
        if args.keep_temp:
            log(f"Keeping temporary directory: {workdir}")
        else:
            try:
                shutil.rmtree(workdir)
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

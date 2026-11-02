#!/usr/bin/env python3
"""Build .deb and .rpm installation packages for Refmon without external networks.

Usage:
    python packaging/build_packages.py [--deb] [--rpm] [--all]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

VERSION = "2.0.0"
RELEASE = "1"
PKG_NAME = "refmon"
MAINTAINER = "Refmon Development Team <refmon@example.org>"
HOMEPAGE = "https://github.com/parsabe/Refmon"
SUMMARY = "Behavioral Reference Monitor & Live Attack Barrier"
DESCRIPTION = (
    "Refmon detects, contains and explains attacks on endpoints and servers\n"
    " by judging behaviour rather than static signatures. It provides\n"
    " real-time CLI mediation tools (refmon guard, refmon lab) and an\n"
    " interactive Reference Monitor GUI (refmon gui) similar to Wireshark\n"
    " for behavioral incident analysis."
)

ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src" / "refmon"
PACKAGING_DIR = ROOT_DIR / "packaging"
BUILD_DIR = ROOT_DIR / "build" / "package_staging"
DIST_DIR = ROOT_DIR / "dist"

CLI_WRAPPER = """#!/usr/bin/env python3
# Refmon Reference Monitor executable launcher
import sys
from pathlib import Path

# Look for refmon package in /usr/share/refmon or /usr/lib/refmon
for candidate in ("/usr/share/refmon", "/usr/lib/refmon"):
    cand_path = Path(candidate)
    if cand_path.is_dir() and str(cand_path) not in sys.path:
        sys.path.insert(0, str(cand_path))
        break

from refmon.cli import main

if __name__ == "__main__":
    sys.exit(main())
"""


def clean_dir(d: Path) -> None:
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True, exist_ok=True)


def stage_files(stage_root: Path) -> None:
    """Populate Linux filesystem tree under stage_root."""
    bin_dir = stage_root / "usr" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    refmon_bin = bin_dir / "refmon"
    refmon_bin.write_text(CLI_WRAPPER, encoding="utf-8")
    refmon_bin.chmod(0o755)

    # Python package modules under /usr/share/refmon/refmon
    share_refmon = stage_root / "usr" / "share" / "refmon" / "refmon"
    share_refmon.mkdir(parents=True, exist_ok=True)
    for root, dirs, files in os.walk(SRC_DIR):
        dirs[:] = [d for d in dirs if d != "__pycache__" and not d.startswith(".")]
        rel = Path(root).relative_to(SRC_DIR)
        dest_dir = share_refmon / rel
        dest_dir.mkdir(parents=True, exist_ok=True)
        for f in files:
            if f.endswith((".pyc", ".pyo")):
                continue
            src_f = Path(root) / f
            dest_f = dest_dir / f
            shutil.copy2(src_f, dest_f)
            dest_f.chmod(0o644)

    # Desktop entry & icon
    app_dir = stage_root / "usr" / "share" / "applications"
    app_dir.mkdir(parents=True, exist_ok=True)
    desktop_src = PACKAGING_DIR / "refmon.desktop"
    if desktop_src.is_file():
        shutil.copy2(desktop_src, app_dir / "refmon.desktop")
        (app_dir / "refmon.desktop").chmod(0o644)

    icon_dir = stage_root / "usr" / "share" / "icons" / "hicolor" / "scalable" / "apps"
    icon_dir.mkdir(parents=True, exist_ok=True)
    icon_src = PACKAGING_DIR / "refmon.svg"
    if icon_src.is_file():
        shutil.copy2(icon_src, icon_dir / "refmon.svg")
        (icon_dir / "refmon.svg").chmod(0o644)

    # Documentation & License
    doc_dir = stage_root / "usr" / "share" / "doc" / "refmon"
    doc_dir.mkdir(parents=True, exist_ok=True)
    readme_src = ROOT_DIR / "README.md"
    if readme_src.is_file():
        shutil.copy2(readme_src, doc_dir / "README.md")
        (doc_dir / "README.md").chmod(0o644)

    license_src = ROOT_DIR / "LICENSE"
    if license_src.is_file():
        shutil.copy2(license_src, doc_dir / "copyright")
        (doc_dir / "copyright").chmod(0o644)


def build_deb() -> Path:
    """Build Debian .deb package."""
    print("== Building Debian package (.deb) ==")
    deb_staging = BUILD_DIR / "deb"
    clean_dir(deb_staging)
    data_dir = deb_staging / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    stage_files(data_dir)

    # Installed-Size calculation (KiB)
    total_size = sum(f.stat().st_size for f in data_dir.glob("**/*") if f.is_file())
    installed_size_kb = max(1, (total_size + 1023) // 1024)

    # Control files
    debian_dir = deb_staging / "DEBIAN"
    debian_dir.mkdir(parents=True, exist_ok=True)

    control_content = f"""Package: {PKG_NAME}
Version: {VERSION}
Section: utils
Priority: optional
Architecture: all
Installed-Size: {installed_size_kb}
Maintainer: {MAINTAINER}
Homepage: {HOMEPAGE}
Depends: python3 (>= 3.10), python3-pydantic, python3-yaml, python3-cryptography
Description: {SUMMARY}
{DESCRIPTION}
"""
    (debian_dir / "control").write_text(control_content, encoding="utf-8")
    (debian_dir / "control").chmod(0o644)

    # Postinst script for desktop database update if desktop-file-utils is installed
    postinst_content = """#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
exit 0
"""
    postinst = debian_dir / "postinst"
    postinst.write_text(postinst_content, encoding="utf-8")
    postinst.chmod(0o755)

    # Compute md5sums of data files
    md5_lines = []
    for f in sorted(data_dir.glob("**/*")):
        if f.is_file():
            rel_path = f.relative_to(data_dir)
            md5 = hashlib.md5(f.read_bytes()).hexdigest()
            md5_lines.append(f"{md5}  {rel_path}\n")
    (debian_dir / "md5sums").write_text("".join(md5_lines), encoding="utf-8")
    (debian_dir / "md5sums").chmod(0o644)

    # Build control.tar.gz
    control_tar = deb_staging / "control.tar.gz"
    with tarfile.open(control_tar, "w:gz") as tar:
        for entry in ("control", "postinst", "md5sums"):
            p = debian_dir / entry
            if p.is_file():
                ti = tar.gettarinfo(str(p), arcname=f"./{entry}")
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                with p.open("rb") as f:
                    tar.addfile(ti, f)

    # Build data.tar.gz
    data_tar = deb_staging / "data.tar.gz"
    with tarfile.open(data_tar, "w:gz") as tar:
        for root, dirs, files in os.walk(data_dir):
            for d in sorted(dirs):
                full_d = Path(root) / d
                rel_d = full_d.relative_to(data_dir)
                ti = tar.gettarinfo(str(full_d), arcname=f"./{rel_d}")
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                tar.addfile(ti)
            for f in sorted(files):
                full_f = Path(root) / f
                rel_f = full_f.relative_to(data_dir)
                ti = tar.gettarinfo(str(full_f), arcname=f"./{rel_f}")
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                with full_f.open("rb") as fp:
                    tar.addfile(ti, fp)

    # debian-binary
    deb_binary = deb_staging / "debian-binary"
    deb_binary.write_text("2.0\n", encoding="ascii")

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    deb_output = DIST_DIR / f"{PKG_NAME}_{VERSION}_all.deb"
    if deb_output.exists():
        deb_output.unlink()

    # Use ar to create .deb archive with exact ordering: debian-binary, control.tar.gz, data.tar.gz
    cmd = [
        "ar",
        "rcs",
        str(deb_output),
        str(deb_binary),
        str(control_tar),
        str(data_tar),
    ]
    subprocess.run(cmd, check=True)
    print(f"Created: {deb_output} ({deb_output.stat().st_size:,} bytes)")
    return deb_output


def build_rpm() -> Path:
    """Build Red Hat .rpm package using rpmbuild."""
    print("== Building RPM package (.rpm) ==")
    rpm_topdir = BUILD_DIR / "rpmbuild"
    clean_dir(rpm_topdir)
    for sub in ("BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS", "tmp"):
        (rpm_topdir / sub).mkdir(parents=True, exist_ok=True)

    stage_dir = rpm_topdir / "BUILD" / f"{PKG_NAME}-{VERSION}"
    stage_dir.mkdir(parents=True, exist_ok=True)
    stage_files(stage_dir)

    spec_content = f"""Name:           {PKG_NAME}
Version:        {VERSION}
Release:        {RELEASE}%{{?dist}}
Summary:        {SUMMARY}
License:        MIT
URL:            {HOMEPAGE}
BuildArch:      noarch
Requires:       python3 >= 3.10, python3-pydantic, python3-pyyaml, python3-cryptography

%description
{DESCRIPTION}

%prep

%build

%install
rm -rf %{{buildroot}}
mkdir -p %{{buildroot}}
cp -a {stage_dir}/* %{{buildroot}}/

%post
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi

%files
/usr/bin/refmon
/usr/share/refmon
/usr/share/applications/refmon.desktop
/usr/share/icons/hicolor/scalable/apps/refmon.svg
%doc /usr/share/doc/refmon/README.md
%doc /usr/share/doc/refmon/copyright

%changelog
* Mon Nov 02 2026 Refmon Team <refmon@example.org> - 2.0.0-1
- Release version 2.0.0 with Live Reference Monitor GUI and Audio Alerts.
"""
    spec_path = rpm_topdir / "SPECS" / f"{PKG_NAME}.spec"
    spec_path.write_text(spec_content, encoding="utf-8")

    cmd = [
        "rpmbuild",
        "-bb",
        "--define",
        f"_topdir {rpm_topdir}",
        "--define",
        f"_tmppath {rpm_topdir}/tmp",
        "--define",
        "_build_id_links none",
        str(spec_path),
    ]
    subprocess.run(cmd, check=True)

    rpm_files = list((rpm_topdir / "RPMS").glob("**/*.rpm"))
    if not rpm_files:
        raise RuntimeError("rpmbuild completed but no .rpm file was found")

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    rpm_output = DIST_DIR / f"{PKG_NAME}-{VERSION}-{RELEASE}.noarch.rpm"
    if rpm_output.exists():
        rpm_output.unlink()
    shutil.copy2(rpm_files[0], rpm_output)
    print(f"Created: {rpm_output} ({rpm_output.stat().st_size:,} bytes)")
    return rpm_output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deb", action="store_true", help="build .deb package")
    parser.add_argument("--rpm", action="store_true", help="build .rpm package")
    parser.add_argument("--all", action="store_true", help="build both .deb and .rpm")
    args = parser.parse_args()

    build_both = args.all or (not args.deb and not args.rpm)
    built = []
    if build_both or args.deb:
        built.append(build_deb())
    if build_both or args.rpm:
        built.append(build_rpm())

    print("\nSummary of built packages:")
    for p in built:
        print(f"  - {p.name} ({p.stat().st_size:,} bytes) in {p.parent}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

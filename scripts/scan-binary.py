#!/usr/bin/env python3
"""Fail closed on binary findings; qualify only GO-2026-5932 without OpenPGP imports.

Run from the exact meshly source checkout after the strict Linux source scan.
The scanner falls back to module precision for stripped binaries (Go #57764).
"""
import json
import os
from pathlib import Path
import subprocess
import sys


def qualify(findings, packages):
    identifiers = {item.get("osv") for item in findings}
    if not identifiers:
        return []
    if identifiers != {"GO-2026-5932"}:
        raise ValueError("unqualified vulnerability findings: " + repr(identifiers))
    prefix = "golang.org/x/crypto/openpgp"
    if any(package == prefix or package.startswith(prefix + "/") for package in packages):
        raise ValueError("OpenPGP is imported; GO-2026-5932 cannot be qualified")
    return sorted(identifiers)


def main():
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    metadata = subprocess.check_output(["go", "version", "-m", binary], text=True)
    settings = dict(line.strip().split("\t", 1)[1].split("=", 1)
                    for line in metadata.splitlines()
                    if line.startswith("\tbuild\t") and "=" in line)
    target = {key: settings[key] for key in ("GOOS", "GOARCH", "CGO_ENABLED")}
    if target["GOOS"] != "linux" or target["CGO_ENABLED"] != "0":
        raise ValueError("expected a static Linux release binary")
    result = subprocess.run([os.environ.get("GOVULNCHECK", "govulncheck"), "-json", "-mode=binary", binary],
                            text=True, capture_output=True, check=True)
    decoder = json.JSONDecoder()
    documents = []
    remaining = result.stdout.strip()
    while remaining:
        document, end = decoder.raw_decode(remaining)
        documents.append(document)
        remaining = remaining[end:].lstrip()
    configs = [item["config"] for item in documents if "config" in item]
    if len(configs) != 1 or configs[0].get("scanner_version") != "v1.9.0":
        raise ValueError("unexpected or missing scanner configuration")
    sboms = [item["SBOM"] for item in documents if "SBOM" in item]
    if len(sboms) != 1 or sboms[0].get("go_version") != "go1.27.3":
        raise ValueError("binary was not built with the reviewed Go 1.27.3 toolchain")
    packages = subprocess.check_output(["go", "list", "-deps", "./cmd/meshly"],
                                      env=os.environ | target, text=True).splitlines()
    findings = [item["finding"] for item in documents if "finding" in item]
    exceptions = qualify(findings, packages)
    print(json.dumps({"binary": binary, "target": target, "scanner": configs[0],
                      "go": sboms[0]["go_version"], "findings": findings,
                      "qualified_module_only_findings": exceptions,
                      "openpgp_imported": any(package == "golang.org/x/crypto/openpgp" or package.startswith("golang.org/x/crypto/openpgp/") for package in packages), "dependency_package_count": len(packages)}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (IndexError, KeyError, ValueError, OSError, subprocess.CalledProcessError) as error:
        print("binary security gate failed: " + str(error), file=sys.stderr)
        sys.exit(1)

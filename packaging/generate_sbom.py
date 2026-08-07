"""Generate a deterministic CycloneDX inventory for installed runtime dependencies."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import uuid
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


ROOT = "log-classification-pipeline"


def _reference(name: str, version: str) -> str:
    return f"pkg:pypi/{canonicalize_name(name)}@{version}"


def _license(distribution: metadata.Distribution) -> str:
    expression = distribution.metadata.get("License-Expression")
    if expression:
        return expression
    legacy = distribution.metadata.get("License")
    if legacy and legacy.strip().casefold() not in {"unknown", ""}:
        return legacy.strip()
    for classifier in distribution.metadata.get_all("Classifier", []):
        prefix = "License :: "
        if classifier.startswith(prefix):
            return classifier.removeprefix(prefix).replace(" :: ", " - ")
    return "NOASSERTION"


def _requirements(
    distribution: metadata.Distribution,
    *,
    root: bool,
) -> list[Requirement]:
    selected: list[Requirement] = []
    for raw_requirement in distribution.requires or []:
        requirement = Requirement(raw_requirement)
        if requirement.marker is not None:
            environment = {"extra": "web" if root else ""}
            if not requirement.marker.evaluate(environment):
                continue
        selected.append(requirement)
    return selected


def build_bom() -> dict[str, object]:
    pending = [canonicalize_name(ROOT)]
    discovered: dict[str, metadata.Distribution] = {}
    edges: dict[str, set[str]] = {}
    while pending:
        requested = pending.pop()
        if requested in discovered:
            continue
        distribution = metadata.distribution(requested)
        canonical = canonicalize_name(distribution.metadata["Name"])
        discovered[canonical] = distribution
        dependencies: set[str] = set()
        for requirement in _requirements(distribution, root=canonical == ROOT):
            dependency_name = canonicalize_name(requirement.name)
            try:
                dependency = metadata.distribution(dependency_name)
            except metadata.PackageNotFoundError:
                continue
            dependency_ref = _reference(
                dependency.metadata["Name"],
                dependency.version,
            )
            dependencies.add(dependency_ref)
            pending.append(dependency_name)
        edges[canonical] = dependencies

    root_distribution = discovered.pop(ROOT)
    root_ref = _reference(ROOT, root_distribution.version)
    python_ref = f"pkg:generic/python@{platform.python_version()}"
    pyinstaller = metadata.distribution("pyinstaller")
    pyinstaller_ref = _reference("pyinstaller", pyinstaller.version)
    components = [
        {
            "type": "framework",
            "bom-ref": python_ref,
            "name": "Python",
            "version": platform.python_version(),
            "purl": python_ref,
            "licenses": [{"license": {"id": "PSF-2.0"}}],
        },
        {
            "type": "framework",
            "bom-ref": pyinstaller_ref,
            "name": "PyInstaller bootloader",
            "version": pyinstaller.version,
            "purl": pyinstaller_ref,
            "licenses": [
                {
                    "expression": (
                        "GPL-2.0-or-later WITH Bootloader-exception"
                    )
                }
            ],
        },
    ]
    dependencies = [
        {
            "ref": root_ref,
            "dependsOn": sorted(edges[ROOT] | {python_ref, pyinstaller_ref}),
        },
        {"ref": python_ref, "dependsOn": []},
        {"ref": pyinstaller_ref, "dependsOn": []},
    ]
    for canonical, distribution in sorted(discovered.items()):
        name = distribution.metadata["Name"]
        reference = _reference(name, distribution.version)
        components.append(
            {
                "type": "library",
                "bom-ref": reference,
                "name": name,
                "version": distribution.version,
                "purl": reference,
                "licenses": [{"license": {"name": _license(distribution)}}],
            }
        )
        dependencies.append(
            {"ref": reference, "dependsOn": sorted(edges.get(canonical, set()))}
        )

    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    timestamp = datetime.fromtimestamp(epoch, tz=UTC).isoformat().replace("+00:00", "Z")
    identity = hashlib.sha256(
        json.dumps(components, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, identity)}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": ROOT,
                "version": root_distribution.version,
                "purl": root_ref,
                "licenses": [{"license": {"id": "MIT"}}],
            },
        },
        "components": components,
        "dependencies": dependencies,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(
        json.dumps(build_bom(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

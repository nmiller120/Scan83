"""Discover script-bearing tag resources in Ignition 8.3 filesystem storage."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List, Optional


TAG_RESOURCE_ROOT = Path(
    "data/config/resources/core/ignition/tag-definition"
)


@dataclass
class TagEventScript:
    provider: str
    tag_path: str
    event: str
    script: str
    source_file: str


def get_tag_resource_root(install_root: Path) -> Path:
    return install_root / TAG_RESOURCE_ROOT


def _provider_and_tag_path(resource_root: Path, path: Path) -> tuple[str, str]:
    """Best-effort context from the 8.3 resource path.

    Ignition 8.3 mirrors Tag Browser paths beneath tag-definition. The first
    relative path component is treated as the provider and the remaining
    directories/file stem as the tag path. JSON content can override these
    values when explicit provider/path fields are present.
    """
    try:
        parts = path.relative_to(resource_root).parts
    except ValueError:
        return "(unknown)", path.stem

    if not parts:
        return "(unknown)", path.stem

    provider = parts[0]
    tag_parts = list(parts[1:])
    if tag_parts:
        tag_parts[-1] = Path(tag_parts[-1]).stem
    tag_path = "/".join(tag_parts) or path.stem
    return provider, tag_path


def _first_string(mapping: dict, keys: Iterable[str]) -> Optional[str]:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _extract_event_scripts(
    node: Any,
    source_file: str,
    provider: str,
    tag_path: str,
) -> List[TagEventScript]:
    found: List[TagEventScript] = []

    if isinstance(node, dict):
        local_provider = _first_string(
            node, ("provider", "providerName", "tagProvider")
        ) or provider
        local_path = _first_string(
            node, ("tagPath", "path", "fullPath", "configuredTagPath")
        ) or tag_path

        event_scripts = node.get("eventScripts")
        if isinstance(event_scripts, list):
            for event_obj in event_scripts:
                if not isinstance(event_obj, dict):
                    continue
                event = _first_string(
                    event_obj, ("eventid", "eventId", "event", "name")
                ) or "(unknown)"
                script = _first_string(
                    event_obj, ("script", "code", "source")
                )
                if script:
                    found.append(TagEventScript(
                        provider=local_provider,
                        tag_path=local_path,
                        event=event,
                        script=script,
                        source_file=source_file,
                    ))
        elif isinstance(event_scripts, dict):
            for event, value in event_scripts.items():
                if isinstance(value, str) and value.strip():
                    found.append(TagEventScript(
                        provider=local_provider,
                        tag_path=local_path,
                        event=str(event),
                        script=value,
                        source_file=source_file,
                    ))
                elif isinstance(value, dict):
                    script = _first_string(value, ("script", "code", "source"))
                    if script:
                        found.append(TagEventScript(
                            provider=local_provider,
                            tag_path=local_path,
                            event=str(event),
                            script=script,
                            source_file=source_file,
                        ))

        for key, value in node.items():
            if key == "eventScripts":
                continue
            found.extend(_extract_event_scripts(
                value, source_file, local_provider, local_path
            ))

    elif isinstance(node, list):
        for value in node:
            found.extend(_extract_event_scripts(
                value, source_file, provider, tag_path
            ))

    return found


def discover_tag_event_scripts(install_root: Path) -> List[TagEventScript]:
    """Parse migrated 8.3 tag-definition JSON and return configured scripts."""
    resource_root = get_tag_resource_root(install_root)
    if not resource_root.is_dir():
        return []

    scripts: List[TagEventScript] = []
    for path in resource_root.rglob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue

        provider, tag_path = _provider_and_tag_path(resource_root, path)
        try:
            source_file = str(path.relative_to(install_root))
        except ValueError:
            source_file = str(path)

        scripts.extend(_extract_event_scripts(
            data, source_file, provider, tag_path
        ))

    return scripts

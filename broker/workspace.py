# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .repository import list_projects_records


@dataclass
class Workspace:
    name: str
    path: str
    provider: str


class WorkspaceManager:
    def __init__(self) -> None:
        self._active_by_session: Dict[str, str] = {}

    def roots(self) -> List[Workspace]:
        home = Path.home()
        candidates = [
            ("new-projects", home / "Documents" / "New project", "local"),
            ("web-projects", home / "Documents" / "web_projects", "local"),
            ("onedrive-home", home / "OneDrive", "onedrive"),
            ("onedrive-cloudstorage", home / "Library" / "CloudStorage" / "OneDrive-Personal", "onedrive"),
            ("icloud-drive", home / "Library" / "Mobile Documents" / "com~apple~CloudDocs", "icloud"),
        ]
        return [
            Workspace(name=name, path=str(path), provider=provider)
            for name, path, provider in candidates
            if path.exists()
        ]

    def discover(self) -> List[Workspace]:
        found: Dict[str, Workspace] = {item.path: item for item in self.roots()}
        for root in self.roots():
            base = Path(root.path)
            try:
                children = sorted(child for child in base.iterdir() if child.is_dir())
            except OSError:
                continue
            for child in children[:100]:
                key = str(child.resolve())
                found[key] = Workspace(
                    name=child.name,
                    path=key,
                    provider=root.provider,
                )

        for project in list_projects_records():
            if project.local_path:
                path = str(Path(project.local_path).expanduser().resolve())
                found[path] = Workspace(
                    name=project.name,
                    path=path,
                    provider="project",
                )

        return sorted(found.values(), key=lambda item: (item.provider, item.name.lower()))

    def set_active(self, session_id: str, identifier: str) -> Workspace:
        workspaces = self.discover()
        identifier_lower = identifier.strip().lower()
        for workspace in workspaces:
            if workspace.name.lower() == identifier_lower or workspace.path.lower() == identifier_lower:
                self._active_by_session[session_id] = workspace.path
                return workspace
        candidate = Path(identifier).expanduser()
        if candidate.exists() and candidate.is_dir():
            resolved = str(candidate.resolve())
            workspace = Workspace(name=candidate.name or resolved, path=resolved, provider="path")
            self._active_by_session[session_id] = workspace.path
            return workspace
        raise KeyError(identifier)

    def get_active(self, session_id: str) -> Optional[Workspace]:
        current = self._active_by_session.get(session_id)
        if not current:
            return None
        path = Path(current)
        if not path.exists():
            self._active_by_session.pop(session_id, None)
            return None
        return Workspace(name=path.name, path=str(path.resolve()), provider="active")

    def resolve_path(self, session_id: str, path_value: str | None = None) -> str:
        if path_value:
            return str(Path(path_value).expanduser().resolve())
        active = self.get_active(session_id)
        if active:
            return active.path
        return os.getcwd()


workspace_manager = WorkspaceManager()

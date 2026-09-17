# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
from __future__ import annotations

from .models import ExecuteCommandRequest, ExecuteCommandResponse, SurgeMode


READ_ONLY_TOOLS = {
    "search.web",
    "search.code",
    "search.memory",
    "project.list",
    "git.inspect",
    "data.analyze",
    "data.scrape",
    "node.status",
}
CONTROLLED_TOOLS = {"app.run", "command.execute", "command.remote", "workflow.run"}


def evaluate_request(request: ExecuteCommandRequest, mode: SurgeMode) -> ExecuteCommandResponse:
    if mode == SurgeMode.LOCKDOWN:
        return ExecuteCommandResponse(
            status="blocked",
            mode=mode,
            approval_required=True,
            summary="Execution blocked in LOCKDOWN mode.",
        )

    if request.tool_name in READ_ONLY_TOOLS:
        return ExecuteCommandResponse(
            status="allowed",
            mode=mode,
            approval_required=False,
            summary="Read-only tool allowed.",
        )

    if request.tool_name in CONTROLLED_TOOLS and mode in {
        SurgeMode.CONTROLLED,
        SurgeMode.AUTONOMOUS,
    }:
        return ExecuteCommandResponse(
            status="allowed",
            mode=mode,
            approval_required=False,
            summary="Controlled tool allowed.",
        )

    return ExecuteCommandResponse(
        status="pending_approval",
        mode=mode,
        approval_required=True,
        summary=(
            "Action requires approval. Review at /dashboard/approvals "
            "(or run `/approvals` in the CLI)."
        ),
    )

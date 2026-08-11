from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, TypeAdapter, model_validator

from xdr_graph.models import IncidentReport
from xdr_graph.response import ResponseCommand
from xdr_graph.response_execution import ActualResponseService, ExecutionResult, ImpactPreview


_command_adapter = TypeAdapter(ResponseCommand)


class PlaybookStep(BaseModel):
    step_id: str = Field(min_length=1)
    command: dict[str, Any]
    depends_on: list[str] = Field(default_factory=list)
    continue_on_error: bool = False


class ResponsePlaybook(BaseModel):
    playbook_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    steps: list[PlaybookStep] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def validate_dependencies(self) -> "ResponsePlaybook":
        identifiers = [step.step_id for step in self.steps]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("playbook step IDs must be unique")
        seen: set[str] = set()
        for step in self.steps:
            if not set(step.depends_on) <= seen:
                raise ValueError("playbook dependencies must reference earlier steps")
            seen.add(step.step_id)
        return self


class PlaybookSimulation(BaseModel):
    playbook_id: str
    allowed: bool
    steps: list[ImpactPreview]


class PlaybookStepResult(BaseModel):
    step_id: str
    status: Literal["succeeded", "failed", "blocked", "skipped"]
    result: ExecutionResult | None = None
    reason: str | None = None


class PlaybookRun(BaseModel):
    playbook_id: str
    status: Literal["succeeded", "partial", "failed", "blocked"]
    steps: list[PlaybookStepResult]


class PlaybookComparison(BaseModel):
    """승인 전 예상과 실제 결과의 차이를 단계별로 남겨 과대 대응을 찾는다."""
    playbook_id: str
    simulation_allowed: bool
    actual_status: str
    steps: list[dict[str, Any]]


class ResponsePlaybookService:
    """Execute bounded response steps sequentially with per-command approvals and auditability."""

    def __init__(self, response_service: ActualResponseService) -> None:
        self.response_service = response_service

    def simulate(self, playbook: ResponsePlaybook, report: IncidentReport) -> PlaybookSimulation:
        if playbook.incident_id != report.incident_id:
            raise ValueError("playbook incident does not match report incident")
        previews = [
            self.response_service.preview_impact(_command_adapter.validate_python(step.command), report)
            for step in playbook.steps
        ]
        return PlaybookSimulation(
            playbook_id=playbook.playbook_id,
            allowed=all(preview.allowed for preview in previews),
            steps=previews,
        )

    def execute(
        self,
        playbook: ResponsePlaybook,
        report: IncidentReport,
        *,
        approvals: dict[str, str],
    ) -> PlaybookRun:
        simulation = self.simulate(playbook, report)
        if not simulation.allowed:
            return PlaybookRun(playbook_id=playbook.playbook_id, status="blocked", steps=[
                PlaybookStepResult(step_id=step.step_id, status="blocked", reason="simulation blocked the playbook")
                for step in playbook.steps
            ])

        results: list[PlaybookStepResult] = []
        succeeded: set[str] = set()
        for step in playbook.steps:
            if not set(step.depends_on) <= succeeded:
                results.append(PlaybookStepResult(step_id=step.step_id, status="skipped", reason="dependency did not succeed"))
                continue
            command = _command_adapter.validate_python(step.command)
            result = self.response_service.execute(
                command,
                report,
                approval_id=approvals.get(command.command_id),
            )
            status = "succeeded" if result.status == "succeeded" else "blocked" if result.status == "blocked" else "failed"
            results.append(PlaybookStepResult(step_id=step.step_id, status=status, result=result))
            if status == "succeeded":
                succeeded.add(step.step_id)
            elif not step.continue_on_error:
                for remaining in playbook.steps[len(results):]:
                    results.append(PlaybookStepResult(step_id=remaining.step_id, status="skipped", reason="previous step failed"))
                break

        statuses = {result.status for result in results}
        overall = "succeeded" if statuses == {"succeeded"} else "failed" if statuses <= {"failed", "skipped"} else "blocked" if statuses <= {"blocked", "skipped"} else "partial"
        return PlaybookRun(playbook_id=playbook.playbook_id, status=overall, steps=results)

    def compare(self, simulation: PlaybookSimulation, run: PlaybookRun) -> PlaybookComparison:
        if simulation.playbook_id != run.playbook_id:
            raise ValueError("simulation and run must reference the same playbook")
        rows = []
        for index, preview in enumerate(simulation.steps):
            result = run.steps[index] if index < len(run.steps) else None
            rows.append({"step_index": index, "expected_allowed": preview.allowed, "actual_status": result.status if result else "missing", "matched": bool(result) and (preview.allowed == (result.status == "succeeded"))})
        return PlaybookComparison(playbook_id=run.playbook_id, simulation_allowed=simulation.allowed, actual_status=run.status, steps=rows)


def ransomware_playbook(
    *,
    incident_id: str,
    terminate_command: dict[str, Any],
    quarantine_command: dict[str, Any],
    network_command: dict[str, Any] | None = None,
) -> ResponsePlaybook:
    """Create the built-in containment sequence; every mutating step still needs approval."""
    steps = [
        PlaybookStep(step_id="stop-process-tree", command=terminate_command),
        PlaybookStep(step_id="quarantine-file", command=quarantine_command, depends_on=["stop-process-tree"]),
    ]
    if network_command:
        steps.append(PlaybookStep(step_id="block-network", command=network_command, depends_on=["stop-process-tree"], continue_on_error=True))
    return ResponsePlaybook(
        playbook_id=f"ransomware-{incident_id}",
        name="랜섬웨어 의심 격리",
        incident_id=incident_id,
        steps=steps,
    )

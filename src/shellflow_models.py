"""Pydantic models and schemas for ShellFlow.

This module provides type-safe interfaces for agent integration, parsing validation,
and structured output serialization using Pydantic.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, ValidationInfo, conint, field_validator

# =============================================================================
# Input Schemas (Agent Integration)
# =============================================================================


class ShellFlowRunArgs(BaseModel):
    """Arguments for running a ShellFlow script.

    This model defines the input schema that agents can use to interact
    with ShellFlow in a type-safe manner.
    """

    script: str = Field(
        ...,
        description="符合 Shellflow 规范的 Bash 脚本内容。使用 # @LOCAL 表示本地执行, # @REMOTE <host> 表示远程执行。",
    )
    dry_run: bool = Field(default=False, description="如果为 true, 则仅解析脚本并验证 SSH 连接, 不实际执行命令。")
    timeout_global: int | None = Field(default=None, description="整个剧本执行的全局超时时间(秒)")


# =============================================================================
# Parsing Validation Models
# =============================================================================


class BlockDirective(BaseModel):
    """Directive configuration for a script block."""

    block_type: Literal["LOCAL", "REMOTE"]
    target: str | None = None
    timeout: Annotated[int, conint(gt=0)] | None = None  # 严格限制必须是正整数
    retry: Annotated[int, conint(ge=0)] | None = 0
    shell: Literal["bash", "zsh", "sh"] = "bash"

    @field_validator("target")
    def validate_target(cls, v: str | None, info: ValidationInfo) -> str | None:  # noqa: N805
        if info.data["block_type"] == "REMOTE" and not v:
            raise ValueError("@REMOTE 必须指定 ssh-host 目标")
        return v


class ScriptBlock(BaseModel):
    """A parsed script block with validation."""

    directive: BlockDirective
    code_lines: list[str]
    source_line: int = 1


# =============================================================================
# Output Schemas (Structured Logging)
# =============================================================================


class CommandTrace(BaseModel):
    """Trace information for a single command execution."""

    command: str
    stdout_chunk: str = ""
    stderr_chunk: str = ""
    exit_code: int | None = None
    status: str = "completed"
    duration_ms: int | None = None


class BlockExecutionResult(BaseModel):
    """Structured result of executing a single block."""

    block_index: int
    status: Literal["success", "failed", "timeout", "retrying"]
    exit_code: int
    exports: dict[str, Any]  # 记录 # @EXPORT 捕获的变量
    duration_sec: float
    traces: list[CommandTrace]
    stdout: str = ""
    stderr: str = ""
    error_message: str = ""

    @property
    def success(self) -> bool:
        """Check if the block execution was successful."""
        return self.status == "success"


class StructuredExport(BaseModel):
    """Configuration for structured JSON export."""

    name: str = Field(..., description="Export variable name")
    json_schema: dict[str, Any] = Field(..., description="JSON schema for validation")
    source: str = Field("stdout", description="Source stream to parse JSON from")


# =============================================================================
# Validation Helpers
# =============================================================================


def validate_json_export(value: str, _schema: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate JSON string.

    Args:
        value: JSON string to validate
        _schema: JSON schema for validation (ignored for now)

    Returns:
        Parsed JSON object

    Raises:
        ValueError: If JSON is invalid
    """
    import json

    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in export: {e}") from e

    # For now, just return the parsed JSON
    # In a full implementation, you might use jsonschema or similar
    return parsed


def create_export_schema_from_pydantic(model_cls: type[BaseModel]) -> dict[str, Any]:
    """Create a JSON schema from a Pydantic model.

    Args:
        model_cls: Pydantic model class

    Returns:
        JSON schema dictionary
    """
    return model_cls.model_json_schema()

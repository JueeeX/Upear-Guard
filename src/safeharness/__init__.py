"""Public API for the framework-agnostic SafeHarness runtime."""

from safeharness.api.context import SessionContext
from safeharness.api.decisions import (
    Decision,
    Disposition,
    EnforcementReceipt,
    Obligation,
    ObligationKind,
    Reason,
    RiskAssessment,
    Severity,
)
from safeharness.api.events import ContentSource, EventKind, EventMeta, SecurityEvent
from safeharness.api.tools import (
    Reversibility,
    ToolDescriptor,
    ToolExecutionOutcome,
    ToolInvocation,
)
from safeharness.adapters.base import (
    BASELINE_REQUIRED_CAPABILITIES,
    PRODUCTION_REQUIRED_CAPABILITIES,
    AdapterCapabilities,
    Coverage,
    DeclaredDeploymentControls,
    DeploymentControls,
)
from safeharness.adapters.langgraph import LangGraphAgent, LangGraphSubagent, LangGraphTool
from safeharness.guard import (
    AgentAdapter,
    AgentAttachment,
    AgentAttachmentError,
    AttachmentReport,
    Guard,
    LifecycleOperationDenied,
    SafeHarnessGuard,
    register_agent_adapter,
    unregister_agent_adapter,
)
from safeharness.runtime import RuntimeConfig, SafeHarnessRuntime, SecuritySession
from safeharness.chat_bridge import (
    ProtectedChatError,
    ProtectedChatRequest,
    ProtectedChatResult,
    ProtectedChatRunner,
)

__all__ = [
    "BASELINE_REQUIRED_CAPABILITIES",
    "ContentSource",
    "Coverage",
    "AgentAdapter",
    "AgentAttachment",
    "AgentAttachmentError",
    "AdapterCapabilities",
    "AttachmentReport",
    "Decision",
    "DeclaredDeploymentControls",
    "DeploymentControls",
    "Disposition",
    "EnforcementReceipt",
    "EventKind",
    "EventMeta",
    "Obligation",
    "ObligationKind",
    "PRODUCTION_REQUIRED_CAPABILITIES",
    "Reason",
    "Reversibility",
    "RiskAssessment",
    "RuntimeConfig",
    "Guard",
    "LifecycleOperationDenied",
    "LangGraphAgent",
    "LangGraphSubagent",
    "LangGraphTool",
    "SafeHarnessGuard",
    "SafeHarnessRuntime",
    "SecurityEvent",
    "SecuritySession",
    "ProtectedChatError",
    "ProtectedChatRequest",
    "ProtectedChatResult",
    "ProtectedChatRunner",
    "SessionContext",
    "Severity",
    "ToolDescriptor",
    "ToolExecutionOutcome",
    "ToolInvocation",
    "register_agent_adapter",
    "unregister_agent_adapter",
]

__version__ = "0.1.0a1"

"""NorthGate RMM Phase 1 synthetic domain slice."""

from northgate_rmm.control_plane import ControlPlane
from northgate_rmm.domain import (
    EndpointHealth,
    EndpointLifecycle,
    EndpointStatus,
    FreshnessPolicy,
    Platform,
)
from northgate_rmm.simulator import SyntheticAgent

__all__ = [
    "ControlPlane",
    "EndpointHealth",
    "EndpointLifecycle",
    "EndpointStatus",
    "FreshnessPolicy",
    "Platform",
    "SyntheticAgent",
]

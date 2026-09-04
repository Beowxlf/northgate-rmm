"""Fail-closed domain errors for the Phase 1 simulator."""


class NorthGateRmmError(Exception):
    """Base class for expected domain failures."""


class ValidationError(NorthGateRmmError):
    """A message or domain value did not satisfy its contract."""


class AuthorizationError(NorthGateRmmError):
    """The authenticated synthetic identity cannot perform the operation."""


class ServiceUnavailableError(NorthGateRmmError):
    """A required private service was unavailable or rejected the request."""


class ReplayError(NorthGateRmmError):
    """A message ID or boot-sequence value was already accepted."""


class NotFoundError(NorthGateRmmError):
    """The requested domain object does not exist."""

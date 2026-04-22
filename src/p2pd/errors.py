"""Custom exception types for the p2pd library."""
# Defines all custon exceptions.

# There's no gateway defined for that address family.
class NoGatewayForAF(Exception):
    """Raised when no gateway is available for the requested address family."""


class InterfaceNotFound(Exception):
    """Raised when the requested network interface cannot be found."""


class InterfaceInvalidAF(Exception):
    """Raised when an address family is not supported by the interface."""


class ErrorNoReply(Exception):
    """Raised when no reply is received within the expected timeframe."""


class ErrorPipeOpen(Exception):
    """Raised when a pipe fails to open."""


class ErrorFeatureDeprecated(Exception):
    """Raised when a deprecated feature is used."""


class ErrorCantLoadNATInfo(Exception):
    """Raised when NAT information cannot be loaded."""


class AlreadyClosedError(Exception):
    """Raised when an operation is attempted on an already-closed resource."""


class TunnelFailed(Exception):
    """Raised when a tunneling operation fails."""


class StartNodeNicknameFailed(Exception):
    """Raised when the node fails to register its nickname."""

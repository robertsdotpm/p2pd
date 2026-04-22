# Defines all custon exceptions.

# There's no gateway defined for that address family.
class NoGatewayForAF(Exception):
    """Raised when no gateway is available for the requested address family."""

    pass


class InterfaceNotFound(Exception):
    """Raised when the requested network interface cannot be found."""

    pass


class InterfaceInvalidAF(Exception):
    """Raised when an address family is not supported by the interface."""

    pass


class ErrorNoReply(Exception):
    """Raised when no reply is received within the expected timeframe."""

    pass


class ErrorPipeOpen(Exception):
    """Raised when a pipe fails to open."""

    pass


class ErrorFeatureDeprecated(Exception):
    """Raised when a deprecated feature is used."""

    pass


class ErrorCantLoadNATInfo(Exception):
    """Raised when NAT information cannot be loaded."""

    pass


class AlreadyClosedError(Exception):
    """Raised when an operation is attempted on an already-closed resource."""

    pass


class TunnelFailed(Exception):
    """Raised when a tunneling operation fails."""

    pass


class StartNodeNicknameFailed(Exception):
    """Raised when the node fails to register its nickname."""

    pass

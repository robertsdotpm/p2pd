# Defines all custon exceptions.

# There's no gateway defined for that address family.
class NoGatewayForAF(Exception):
    pass

class InterfaceNotFound(Exception):
    pass

class InterfaceInvalidAF(Exception):
    pass
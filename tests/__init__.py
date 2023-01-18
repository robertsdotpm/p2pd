try:
    from p2pd.test_init import *

    from .static_route import *
except Exception:
    from static_route import *

    from p2pd.test_init import *

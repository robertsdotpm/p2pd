import multiprocessing

TRY_OVERLAP_EXTS = 1
TRY_NOT_TO_OVERLAP_EXTS = 2
CON_ID_MSG = b"P2P_CON_ID_EQ"

# No more than n interfaces per address family in peer addr.
NODE_ADDR_MAX_INTERFACES = 4

# No more than n signal pipes to send signals to nodes.
SIGNAL_PIPE_NO = 3

shut_down = multiprocessing.Event()
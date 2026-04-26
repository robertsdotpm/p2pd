"""UDP hole-punch traversal plugin sub-package.

Reuses tcp_punch's NAT prediction + boundary timing for the rendezvous
phase. The fire/verify engine is UDP-specific because UDP is connection-
less: there's no SYN/SYN-ACK race, just a sendto() spray + an inbound
listen with an app-level CONFIRM probe to validate the mapping was
real (not random scanner traffic).
"""

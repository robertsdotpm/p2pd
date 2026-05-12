"""In-band ConId rendezvous frame for direct_connect.

The initiator writes this frame as the very first bytes on a
freshly-established TCP pipe so the responder's node_protocol can
peel it off and resolve the reverse_connect inbound future for the
matching plugin_id. Same channel as the data pipe = no cross-channel
race with a separate signal-pipe round-trip.

Wire format:

    b"P2P-CID:" + plugin_id + b"\\n"

ASCII-only. plugin_id is the alphanumeric token already chosen by
auto_connect; no JSON, no encryption, no length prefix needed for a
single-shot frame whose entire content is one short ID.
"""

CON_ID_PREFIX = b"P2P-CID:"

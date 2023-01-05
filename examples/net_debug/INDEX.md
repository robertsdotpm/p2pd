# Net debug

When you write network software there's usually a bunch of basic
questions you would like to answer. Such questions might include:

- What is my IP?
- What 'port' is 'mapped' to my connection (if it's TCP.)
- Is my service on port X, protocol Y 'reachable' on the Internet?
- Can you send data to a service to check if it's 'usable.'
- Basic echo service for testing data receipt.
- Possibly APIs that simulate lag and 'buffer bloat' issues with networking.

Currently I have reason to have data sent to a service to check
whether or not a TURN relay address is 'usable' and reaches a client
successfully. In the softare 'Coturn' a recent update seems to have
removed the ability to send data to yourself. Hence a third-party
service is needed for testing.

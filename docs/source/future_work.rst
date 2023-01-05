Future work
=============

Network changes
-----------------

What most production software has is some kind of logic to detect network changes. Events like disconnects, external IP changes, changes to the gateway,
or active NIC, allow the program to react to changes. I'd like to eventually have
code to detect such changes on all major operating systems. Then give pipes the
ability to add handlers for such events. This would make it very easy to engineer
highly reliable networking software.

Firewall bypass
-----------------

Windows-based operating systems include firewalls that will prompt the user if they
want to allow an application to use the Internet. Mac OS X has similar security
measures. A user without much experience may not know what to do. It would
be a good idea to automatically setup rules to allow P2PD to use the Internet
on various platforms. I'd also like to put some work into packaging in the future so that this software is as easy to use as possible.

Pushing sockets
----------------

One common criticism against Python is that 'it's slow.' I don't believe this is the
case but let's suppose that it is. Let's suppose that an engineer has a very good
reason not to use something like P2PD for their peer-to-peer networking code
e.g. they may have already written highly optimized networking code themselves.
Well, it's possible to pass a socket from one process to another.
What this could mean is that P2PD could specialize in the initial process of
openning up connections with remote peers and then passing those bound sockets
to other processes to use as they see fit.

I think this could be a really cool option because it would allow engineers to
reuse their existing networking code. Maybe they have a different event loop.
Maybe they use a model based on threads and polling. They would be able to use
the networking features they're already familar with for their respective
software stacks. I think it's an interesting idea.

Error recovery code
---------------------

As I sit here reflecting on this project I'm reminded of just how many ways
networking code can fail versus regular algorithms. As an example: on Windows
if you switch between wireless networks there can be a delay until being able to
use that interface for Internet traffic. I don't know why that is. It may be an
issue with router advertisements and ARP. But what I know is any code that
runs shortly after the network is changed is likely to fail despite having
'correct' addressing information.

I think it would be worthwhile making a list of common failure scenarios and writing
code to prevent it from occuring. Really only the most basic networking features
are provided in programming languages. There are many other ways sessions can fail
and most developers manually handle the edge-cases themselves (like reconnect.)

Other ideas
-------------

1.  Send duplicate signaling msgs in case a MQTT server goes down.
2.  Ability to restart broken TCP connections after disruptions in Internet. Many
    simple servers start a fresh state per connection and in some scenarios (like
    multiplayer games -- it can mean being unable to rejoin sessions.) 
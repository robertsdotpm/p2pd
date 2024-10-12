Future work
===============

Network changes
-----------------

Most production software has a way to detect network changes. Events like
disconnects, IP changes, gateway changes, or default NIC changes-- make the program
more robust. I'd like to eventually have code to detect these changes for all
major operating systems. Then give pipes handlers for such events.

Firewall bypass
-----------------

Windows-based systems include firewalls that can interfere with some programs.
Mac OS X has similar security measures. It would be a good idea to automatically setup rules
to allow P2PD to use the Internet on various platforms.

Pushing sockets
----------------

One common criticism against Python is that 'it's slow.' I don't believe this is the
case but let's suppose it is. Let's suppose that an engineer has a very good
reason not to use something like P2PD for their peer-to-peer networking code
e.g. they may have already written highly optimized networking code themselves.
Well, it's possible to pass a socket from one process to another.
What this means is P2PD could specialize in the initial process of
opening connections to peers and then passing those bound sockets
to other processes to use as they see fit.

I think this could be a cool option because it would allow engineers to
reuse existing networking code. Maybe they have a different event loop.
Maybe they use a model based on threads and polling. If you could pass sockets around
an engineer could use any networking features they're already familiar with.

Error recovery code
---------------------

As I sit here reflecting on this project I'm reminded how many ways
networking code can fail. As an example: on Windows
if you switch between wireless networks there can be a delay until being able to
use that interface for Internet traffic. I don't know why that is. It may be an
issue with router advertisements and ARP. But what I know is any code that
runs shortly after the network is changed is likely to fail despite having
'correct' addressing information.

I think it would be worthwhile making a list of common failure scenarios and writing
code to prevent it from occurring. Really, only the most basic networking features
are provided in most programming languages. There are many other ways
sessions can fail and most developers manually handle the edge-cases
themselves (badly e.g. reconnect loops.)

Other ideas
-------------

1.  Send duplicate signaling msgs in case a MQTT server goes down.
2.  Ability to restart broken TCP connections after disruptions in Internet. Many
    simple servers start a fresh state per connection and in some scenarios (like
    multiplayer games -- it can mean being unable to rejoin sessions.)
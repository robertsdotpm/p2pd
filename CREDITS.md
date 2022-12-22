# Credits

The new version of p2pd features code from multiple sources that have been heavily modified. It's my intention to try document all these sources but if I've somehow missed some please don't assume this is intentional!

- STUN: https://github.com/talkiq/pystun3 which is itself a fork from https://github.com/jtriley/pystun Numerous changes made to the code -- see file for more info.
- clock_skew: taken from the original gtk-gnutella code and adapted to python by me https://github.com/gtk-gnutella/gtk-gnutella/
blob/devel/src/core/clock.c 
- dhcp: hassanes DHCP socket code at active state https://code.activestate.com/recipes/577649-dhcp-query/ I made it async and added a DHCP option that requests a specific IP and lease.
- set interface IP script for powershell from: https://www.pdq.com/blog/using-powershell-to-set-static-and-dhcp-ip-addresses-part-1/
- sip_client: https://github.com/SythilTech/Python-SIP/blob/master/scripts/sip.py adapted to be async.
- turn_client: https://github.com/trichimtrich/turnproxy original code was for TCP proxying. I heavily modified it and changed it to use the UDP data channels feature of TURN.
- All the amazing open source authors whose modules I have used! Their respective works are listed in the requirements.txt file where more information can be found on Pypy.

Additionally, there were countless technical references I consulted throughout this project. It isn't possible to list all of them - but this project wouldn't exist without everyone who openly shared knowledge and source code.

Thanks everyone!

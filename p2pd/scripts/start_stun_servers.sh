# In a screen:
./stunserver --mode full --family 4 --protocol udp &
./stunserver --mode full --family 6 --protocol udp &
./stunserver --mode full --family 4 --protocol tcp &
./stunserver --mode full --family 6 --protocol tcp &



./stunserver --mode full --family 6 --protocol udp --primaryinterface 2a01:4f8:10a:3ce0::2 --altinterface 2a01:4f8:10a:3ce0::3
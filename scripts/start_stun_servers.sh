# In a screen:
./stunserver --mode full --family 4 --protocol udp &
./stunserver --mode full --family 6 --protocol udp &
./stunserver --mode full --family 4 --protocol tcp &
./stunserver --mode full --family 6 --protocol tcp &



./stunserver --mode full --family 6 --protocol udp --primaryinterface ipa --altinterface ipb

./stunserver --family 4 --protocol tcp
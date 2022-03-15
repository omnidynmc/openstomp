#!/bin/bash
svn update &&
make makeall &&
killall -INT openstomp &&
sleep 30 &&
./openstomp.botchk &&
cd logs &&
tail -f openstomp.stomp.log

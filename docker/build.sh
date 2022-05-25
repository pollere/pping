#!/bin/sh -e
T=/target/docker
[ -e $T/build.sh ] || (echo "Please use \"./go.sh [static]\" to build, this script is meant to run inside the container"; exit 1)
if [ -z "$ECHO" ]; then  # set ECHO=echo to see completed commands instead of running them
false && ( 
#sed this to false to disable debugging... and dont add any "false" or "false" before this or sed globally... :-|
 echo "$T:"; ls -l $T
 echo "Disabling image interactive console mode for next run..."
 sed -i s@false@false@ $T/build.sh 
 cd /usr/src/build
 echo "--- Here are the build commands: ---"
 ECHO=echo $T/build.sh
 echo "please \"exit\" when done..."
 echo "BUILD=$BUILD $T/build.sh # if you want to see it again or for static/dynamic"
 echo "The docker image will also be reused to create a new container if you change build using ./go.sh [static|dynamic]"
 echo "/usr/src/build:"; 
 ECHO=echo /bin/bash
 exit 1
); 
fi; 

echo Building tins...
if [ -n "$ECHO" ] ||  [ \! -d /usr/src/build ]; then
 $ECHO mkdir /usr/src/build
 $ECHO cd /usr/src/build
 if [ "$BUILD" = "static" ]; then
 $ECHO  cmake $T/libtins -DLIBTINS_BUILD_SHARED=0 -DLIBTINS_ENABLE_CXX11=1 -DLIBTINS_ENABLE_ACK_TRACKER=0 -DLIBTINS_ENABLE_WPA2=0  
 else
 $ECHO  cmake $T/libtins -DLIBTINS_ENABLE_CXX11=1 -DLIBTINS_ENABLE_ACK_TRACKER=0 -DLIBTINS_ENABLE_WPA2=0
 fi
fi
$ECHO cd /usr/src/build
$ECHO make -j$(nproc)  # fixme 

echo Building tins example dns_stats...
if [ "$BUILD" = "static" ]; then
 $ECHO g++ $T/libtins/examples/dns_stats.cpp -o dns-stats -ltins -lpthread `pcap-config --libs --static` -std=c++11 -static -I$T/libtins/include -L./lib
else
 $ECHO g++ $T/libtins/examples/dns_stats.cpp -o dns-stats -ltins -lpthread `pcap-config --libs` -std=c++11 -I$T/libtins/include -L./lib
fi
$ECHO cp dns-stats $T
$ECHO strip $T/dns-stats

echo Building pping...
if [ "$BUILD" = "static" ]; then
 $ECHO g++ -I$T/libtins/include -std=c++14 -g -O3 -Wall -o pping /target/pping.cpp -L./lib -ltins `pcap-config --libs --static` -static -lpthread
else
 $ECHO g++ -I$T/libtins/include -std=c++14 -g -O3 -Wall -o pping /target/pping.cpp -L./lib -ltins `pcap-config --libs` -lpthread

 echo "Hopefully you have these dynamic libraries..." 
 if [ -n $ECHO ]; then 
	 echo "(ldd dns-stats;ldd pping)|grep -v found|awk '{print $3}'|grep lib|sort|uniq" # this is the only line for which the ECHO trick doesn't work
 else
	 (ldd dns-stats;ldd pping)|grep -v found|awk '{print $3}'|grep lib|sort|uniq
 fi
 $ECHO cp -v ./lib/libtins.so.* $T
fi
$ECHO cp pping $T
$ECHO strip $T/pping


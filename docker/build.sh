#!/bin/sh -e
T=/target/docker
[ -e $T/build.sh ] || (echo "Please use \"./go.sh [static]\" to build, this script is meant to run inside the container"; exit 1)
false && ( #sed this to false to disable debugging... and don't use those words ANYWHERE else :-p
 echo "$T:"; ls -l $T
 cd /usr/src/build
 echo "cat $T/build.sh # if you want to try it manually"; 
 echo "please \"exit\" when done..."
 echo "/usr/src/build:"; 
 /bin/bash
 echo "Disabling image interactive console mode..."
 sed -i s@false@false@ $T/build.sh 
 exit 1
); 

echo Building tins...
if [ \! -d /usr/src/build ]; then
 mkdir /usr/src/build
 cd /usr/src/build
 if [ "$BUILD" = "static" ]; then
  cmake $T/libtins -DLIBTINS_BUILD_SHARED=0 -DLIBTINS_ENABLE_CXX11=1 -DLIBTINS_ENABLE_ACK_TRACKER=0 -DLIBTINS_ENABLE_WPA2=0  
 else
  cmake $T/libtins -DLIBTINS_ENABLE_CXX11=1 -DLIBTINS_ENABLE_ACK_TRACKER=0 -DLIBTINS_ENABLE_WPA2=0
 fi
fi
cd /usr/src/build
make -j8

echo Building tins example dns_stats...
if [ "$BUILD" = "static" ]; then
 g++ $T/libtins/examples/dns_stats.cpp -o dns-stats -ltins -lpthread `pcap-config --libs --static` -std=c++11 -static -I$T/libtins/include -L./lib
else
 g++ $T/libtins/examples/dns_stats.cpp -o dns-stats -ltins -lpthread `pcap-config --libs` -std=c++11 -I$T/libtins/include -L./lib
fi
cp dns-stats $T
strip $T/dns-stats

echo Building pping...
if [ "$BUILD" = "static" ]; then
 g++ -I$T/libtins/include -std=c++14 -g -O3 -Wall -o pping /target/pping.cpp -L./lib -ltins `pcap-config --libs --static` -static
else
 g++ -I$T/libtins/include -std=c++14 -g -O3 -Wall -o pping /target/pping.cpp -L./lib -ltins `pcap-config --libs`
 echo "Hopefully you have these dynamic libraries..." 
 (ldd dns-stats;ldd pping)|grep -v found|awk '{print $3}'|grep lib|sort|uniq
 cp -v ./lib/libtins.so.* $T
fi
cp pping $T
strip $T/pping


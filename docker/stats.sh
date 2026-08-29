#!/bin/bash

[ -z "$myip" ] && log=log

echo sudo LD_LIBRARY_PATH=. ./pping -i br0 -m \> \$log \# for this script to give stats

[ -z "$myip" ] && myip=192.168.1.2
[ -z "$dest" ] && dest=192.168.1.1
[ -z "$lan" ] && lan=`echo $myip|cut -d. -f1-2`
[ -z "$port" ] && port=443
[ -z "$prec" ] && prec=6 # precision digits+2 ie range 2..8 = 0..6

if [ \! -e $log ]; then
 echo myip=$myip dest=$dest lan=$lan port=$port prec=$prec $0 \# to get stats
 exit;
fi

echo --- only to $dest
grep $dest $log|cut -d\  -f3|cut -b1-$prec|sort -n|uniq -c
echo --- only $lan\*
grep $lan $log|cut -d\  -f3|cut -b1-$prec|sort -n|uniq -c
echo --- not $lan \(ie only other\)
sed s@$myip@@g < $log |grep -v $lan|cut -d\  -f3|cut -b1-$prec|sort -n|uniq -c
echo --- only port :$port\*
grep -v :$port $log |cut -d\  -f3|cut -b1-$prec|sort -n|uniq -c
echo --- top hosts 
sed s@$myip@@g < $log|cut -d\  -f7|cut -d: -f1|sort|uniq -c|sort -n




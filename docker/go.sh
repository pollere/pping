#!/bin/sh 
[ -z "$1" ] && B=dynamic || B=static
E=docker-container-$B.id
./get.sh 
echo Building "$B"ally...
echo Build image...
docker build --iidfile docker-image.id .
echo Renaming old binaries...
cp dns-stats dns-stats.old
cp pping pping.old
rm dns-stats pping
echo Building new ones...
I=`cut -d: -f2 docker-image.id`
[ -e $E ] && (
 docker ps -a|grep `cat $E` && docker start -i `cat $E`
) || ( 
 [ -e $E ] && rm $E
 sed -i s@true@false@ build.sh 
 docker run --cidfile $E -v "$(pwd)/..":/target -e "BUILD=$B" -ti $I /target/docker/build.sh )
D=`cat $E`
ls -l dns-stats pping && echo "Done!" || echo "Failed :-("
echo "# For interactive build environment console:"
echo "sed -i s@false@true@ build.sh; docker start -i $D"
echo "# To clean up:"
echo "docker rm $D; docker rmi $I"

#!/bin/sh 
[ "$1" = "static" ] && B=static || B=dynamic
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
D=`cat $E`
if docker ps -a --no-trunc|grep $D; then
  docker start -i $D 
else 
 [ -e $E ] && rm $E
 sed -i s@true@false@ build.sh 
 docker run --cidfile $E -v "$(pwd)/..":/target -e "BUILD=$B" -ti $I /target/docker/build.sh 
 D=`cat $E`
fi
ls -l dns-stats pping && echo "Done!" || echo "Failed :-("
echo "# For interactive build environment console:"
echo "sed -i s@false@true@ build.sh; docker start -i $D"
echo "# To clean up:"
echo "docker rm $D; docker rmi $I"
echo "either do this, or rm *.id before editing the Dockerfile"

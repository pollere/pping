echo Press ENTER to remove containers
read
for a in *container*.id; do docker rm `cat $a`; done
echo Press ENTER to remove images
read
for a in *image*.id; do docker rmi `cat $a`; done


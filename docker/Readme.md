### Easy build environment


#### Static build:
    
    # ./go.sh static
    
#### Dynamic build:

    # ./go.sh

#### Details

In the interests of saving you a few hours getting pping running, I've scripted the process with the right flags and dependencies to get you binaries with one of the above one-liners.  

Only Linux binaries are currently scripted, and the only dependency is Docker. Compiled binaries and libraries are dropped in the current directory.

Some rudimentary help is built in to get you off to a running start adding support for more build environments or platforms. This was inspired by the build not working on my default environment - a static build using Ubuntu 16.04 in Docker and copying over the binaries solved the problem.

You can try other build environments by playing around with the Dockerfile. 

The build scripts currently does the following: 
* downloads the dependencies locally (get.sh)
* then creates a basic image with the right dependencies. (go.sh) 
* mounts the current directory inside a docker container based on the image, and runs the associated build script. 

The docker container starts up with the build.sh script. Docker doesn't elegantly allow you to change things without creating new containers, so to keep things simple you can simply edit build.sh script and then docker start -i (interactive) the image to change what it does when it starts.

*Having a docker CMD (start command) that's on a mounted volume, of course goes against everything the docker developers stand for. Docker has matured, maybe next time I'll do it differently. For now **this way saves a lot of time, space and effort.**  :-p*
 
Update: Look! Binaries! They may or may not work... they work on my machines... I have accidentally committed them from my build. 

    # shasum dns-stats pping
    12b16a1640983820bee65ae7491f79a800fd1abf  dns-stats
    7b1234a310360de46e0ec5e5a6ee9dd0f712a3dc  pping

#### No build!

Copy and paste this in your terminal:

    wget 'https://github.com/dagelf/pping/blob/master/docker/pping?raw=true' -O pping && shasum pping|grep 7b1234a310360de46e0ec5e5a6ee9dd0f712a3dc && (chmod +x pping; echo "OK!") || echo "Please mail me this binary so we can see what nefarious changes slipped into it in the dark corners of the internet on its way to you... O_o End of the world kind of stuff, either that, or bit rot, better take a look!" # congratulations, now if only everyone checked random web script like you... this only counts if you're reading this on github.com of course. Wow, I'm overthinking things... India rubbed off on me. Or maybe it's all the singing and rural animal noises outside. 

And then try it out:

    # ip link # find the interface you want to monitor, then...
    # sudo LD_LIBRARY_PATH=. ./pping -i eth0 -f "not tcp port 22"


#### Footnote

Docker has gotten some new features since I last used it... which makes "the docker way" more palatable. So you may wonder why I'm not just using a Dockerfile for everything and getting rid of the volume. I could... initially docker was touted as a way to make builds portable. That's what I'm using it for. Portable LOCAL builds. I like the fact that I can edit and work from my local git repository without needing it needlessly duplicated into a container. Although, "the docker way" will work even if the container isn't on my local machine, so maybe I'll do it that way next time.

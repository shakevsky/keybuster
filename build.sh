#!/bin/sh
~/android-ndk-r21/ndk-build -C jni $@

if [ "$1" = clean ]
then
    rm -rf obj/ libs/
fi

#!/bin/bash
${ANDROID_NDK}/ndk-build
mkdir -p ../libs/armeabi-v7a/
cp ../libs/armeabi/libotrjni.so ../libs/armeabi-v7a/

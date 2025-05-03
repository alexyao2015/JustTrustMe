#!/usr/bin/env bash
# This runs inside the container

set -eux -o pipefail

# Configure a tmp home for unknown users
export HOME=/tmp/builduser
mkdir -p $HOME || true

mkdir -p $GRADLE_USER_HOME || true
mkdir -p $ANDROID_HOME || true

# Accept Android SDK licenses
yes | sdkmanager --licenses --sdk_root="${ANDROID_HOME}" || true

# Build the app
./gradlew build
mkdir -p output/apk || true
mkdir -p output/reports || true
mv app/build/outputs/apk/release/*.apk output/apk
mv app/build/reports/*.html output/reports

#!/bin/bash

cd ./src

javac -d clout ./client/*

java -cp clout client.TlsClient $1

rm -r clout

cd ..
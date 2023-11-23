#!/bin/bash

cd ./src/servers

javac -d mdout ./MainDispatcher/*
java -cp mdout servers.MainDispatcher.MainDispatcherServer

rm -r mdout

cd ../..
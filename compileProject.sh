#!/bin/bash

genNewCerts(){
    cd ./certs
    /bin/bash genFServerCrypto.sh
    cd ..
}

javac -d out ./src/utils/*
javac -d out ./src/utils/* ./src/client/*
javac -d out ./src/utils/* ./src/servers/MainDispatcher/*
javac -d out ./src/utils/* ./src/servers/AuthenticationServer/*

genNewCerts

echo "Project Compiled."
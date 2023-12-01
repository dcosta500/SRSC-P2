#!/bin/bash

genNewCerts(){
    cd ./certs
    sh genCerts.sh
    cd ..
}

while getopts ":g" opt; do
  case $opt in
    g)
      genNewCerts
      ;;
    \?)
      echo "Invalid option: -$OPTARG"
      echo "Usage: $0 [-g]"
      exit 1
      ;;
  esac
done

compileJava(){
  javac -d out ./src/utils/* ./src/client/responseModels/* ./src/client/Client.java ./src/client/ClientCommands.java
  javac -d out ./src/utils/* ./src/servers/MainDispatcher/*
  javac -d out ./src/utils/* ./src/servers/AuthenticationServer/*
  javac -d out ./src/utils/* ./src/servers/AccessControlServer/*
  javac -d out ./src/utils/* ./src/servers/StorageSystemService/*

  echo "Project Compiled."
}

buildAndRunDocker(){
  docker build -t srsc_p2_image -f Dockerfile .
  echo "Docker image deployed"

  docker compose -p service_request_network up -d
  echo "Dockers deployed"
}

compileJava
buildAndRunDocker
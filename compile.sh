#!/bin/bash

docker_tag=srsc_p2

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

removeDockerImage(){
  # 1- name of container
  docker rmi "${1}:${docker_tag}"
}

resetDocker(){
  # Remove any previous container instances
  docker compose -p service_request_network down

  # Remove images
  removeDockerImage main_dispatcher
  removeDockerImage auth_server
  removeDockerImage access_control
  removeDockerImage storage_service
}

buildAndRunDocker(){
  docker compose -p service_request_network up -d
  echo "Dockers deployed"
}

compileJava
resetDocker
buildAndRunDocker
#!/bin/bash

docker_tag=srsc_p2
client_name="null"

genNewCerts(){
    cd ./certs
    sh genCerts.sh
    cd ..
}

resetClientFiles(){
  rm -r ./clientFiles/getRoot
}

runClient(){
  if [ "$client_name" != "null" ]; then
    echo "\v"
    echo "Starting client on ${client_name}'s computer..."
    sleep 2 # Give time for Docker to start
    sh runC.sh $client_name
  fi
}

compileJava(){
  echo "Compiling project..."
  rm -r target

  set -e # Abort script on javac errors

  mvn package

  #javac -d out ./src/utils/* ./src/client/responseModels/* ./src/client/Client.java ./src/client/ClientCommands.java\
  #./src/client/ClientValidator.java ./src/client/ClientTokens.java
  #javac -d out ./src/utils/* ./src/servers/MainDispatcher/*
  #javac -d out ./src/utils/* ./src/servers/AuthenticationServer/*
  #javac -d out ./src/utils/* ./src/servers/AccessControlServer/*
  #javac -d out ./src/utils/* ./src/servers/StorageSystemService/*

  set +e # Disable aborting

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

# Parses command flags (cannot be inside a function)
while getopts ":gc:" opt; do
  case $opt in
    g)
      genNewCerts
      ;;
    c)
      client_name="$OPTARG"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument (client name)." >&2
      exit 1
      ;;
  esac
done

resetClientFiles
compileJava
resetDocker
buildAndRunDocker
runClient
#!/bin/bash

docker_tag=srsc_p2
client_name="null"

genNewCerts(){
    cd ./certs
    sh genCerts.sh
    cd ..
}

runClient(){
  if [ "$client_name" != "null" ]; then
    sleep 1 # Give time for Docker to start
    echo "\v"
    echo "Running client ${client_name}..."
    sh runC.sh $client_name
  fi
}

compileJava(){
  echo "Compiling project..."

  javac -d out ./src/utils/* ./src/client/responseModels/* ./src/client/Client.java ./src/client/ClientCommands.java
  javac -d out ./src/utils/* ./src/servers/MainDispatcher/*
  javac -d out ./src/utils/* ./src/servers/AuthenticationServer/*
  javac -d out ./src/utils/* ./src/servers/AccessControlServer/*
  javac -d out ./src/utils/* ./src/servers/StorageSystemService/*

  # echo -ne "\033[K"
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

compileJava
resetDocker
buildAndRunDocker
runClient
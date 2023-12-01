genNewCerts(){
    cd ./certs
    /bin/bash genCerts.sh
    cd ..
}

rm log.txt # deletes debug log file

javac -d out ./src/utils/* ./src/client/responseModels/* ./src/client/Client.java ./src/client/ClientCommands.java
javac -d out ./src/utils/* ./src/servers/MainDispatcher/*
javac -d out ./src/utils/* ./src/servers/AuthenticationServer/*
javac -d out ./src/utils/* ./src/servers/AccessControlServer/*
javac -d out ./src/utils/* ./src/servers/StorageSystemService/*

# genNewCerts

echo "Project Compiled."

docker build -t main_dispatcher -f Dockerfile .
docker build -t authentication_server -f Dockerfile1 .
docker build -t access_control -f Dockerfile2 .
docker build -t storage_service -f Dockerfile3 .

echo "Docker image deployed"

docker-compose up -d

echo "Dockers deployed"
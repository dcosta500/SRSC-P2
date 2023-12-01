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

# genNewCerts

echo "Project Compiled."
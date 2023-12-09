<div align="center">
    <h1>&lt SRSC Project 2 - 23/24 /&gt </h1>
    Diogo Costa - Tomás Gabriel - Tomé Dias - Francisco Vasco
</div>

## Table of Contents

- [How to compile and run](#how-to-compile-and-run)
- [Overview](#overview)
- [Architecture](#architecture)
- [Technologies Used](#technologies-used)
- [Client Commands](#client-commands)
- [Additional Notes](#additional-notes)
- [Authors](#authors)

## How to compile and run
> [!IMPORTANT]
> To make TLSv1.1 work you will need to [modify your _java.security_](#--tlsv11).

### - Compilation Script
To compile all the code and put the servers up and running on Docker, use the following
command. This script will stop all container instances, delete their images, compile the
java code, rebuild the images and launch the containers through Docker Compose.

```
sh compile.sh -g
```

The _-g_ flag is used to generate all necessary public-key cryptography keys and certificates.
It is not necessary to use this flag more than once, unless you need/want to (or if you
really like to wait).

The compilation script can also accept the _-c [name]_ flag if you wish to immediately run the
client script, in the same terminal.

```
sh compile.sh -c [name]
```

> [!NOTE]
> Both flags can be used together.

### - Run Client Script
If the code is already compiled and the servers are already running, you can use the following
command to run a client.

```
sh runC.sh [name]
```

This way, the users' files are preserved between sessions.

## Overview
This is the second project for SRSC-22/23. We developed a **Service Request Network**
where a user can **authenticate**, **request access** and **use** our developed servers and
their services. For this project, only a **File Managing Service** is available.

Running the Client application with name "alice" (for example) means that you are in alice's
computer. You cannot log into another user's account while on your computer.

Your local files are stored in your "_putRoot_" directory, located at "_clientFiles/putRoot_".
For example, alice can only "put" her files, not others'. In contrast, when you do a "get"
for the first time, it will create a "_getRoot_" folder inside your "_clientFiles_". For example,
if bob "get"s a file from alice, it will appear locally in bob's "_getRoot_" inside of the
alice's folder. Putting it simply, in "_putRoot_" you only have access to your folder, in
"_getRoot_" you have access to every folder.

### - File Managing Service
In this service, each client has a folder of their own. For academic purposes, anyone with 
"_read and write_" permissions can put files in each other's folders, "_read_" permissions does
not let you write files, only read, and "_deny_" permission does not let you do any operations
of the service.

### - Clients
Our project has no registration feature, so we have created 5 pre-made clients for you to use.

- Alice (read-write) - **uid**: alice, **pwd**: alice123456
- Bob (read-write) - **uid**: bob, **pwd**: bob123456
- Carol (read) - **uid**: carol, **pwd**: carol123456
- David (deny) - **uid**: david, **pwd**: david123456
- Eric (deny) - **uid**: eric, **pwd**: eric123456

## Architecture

Consider the following picture, the four nodes in the center and right side represent our
network of servers.

<div align="center">
    <img src="https://i.imgur.com/RK8gxO6.png" alt="Screenshot of the project's architecture." width="400"/>
</div>


- **Main Dispatcher (MD)**: The Main Dispatcher can be seen as the
messenger of the other three, and it is the only server that the client will ever
talk directly to.


- **Authentication Server (AS)**: The Authentication Server has information about all
pre-registered users of the network. This node is used to log into the system. If the
login is successful, this server will return, among other things, a ticket to use while
requesting access with the Access Control Server.


- **Access Control Server (AC)**: The Access Control Server has information about all users
of the network and their permissions for each and every service available (only 1 for the
scope of this project). If permission is granted, this server will return a ticket to be
used with the requested service.


- **Storage Service (S)**: The Storage Service stores all the users' files. The users can do
multiple operations in this storage service. Check them all in the [Client Commands](#client-commands) section.

## Technologies Used

### - Docker
All servers of our network are run in **Docker** containers and managed using **Docker Compose**
for an easier server deployment. This also allowed us to put in practice some of the subjects
discussed in our _Cloud Computing_ course.

### - SQLite
Instead of using static _.conf_ files to store client information, we decided to use a database
lightweight solution like SQLite. We could not figure out how to use it with maven, so we ultimately
had to use its .jar manually.

### - TLS Sockets
For client-server communication we adopted the TLS Sockets approach. The handshake process is
customizable via the _.conf_ files located at "_configs/tlsConfig_".

### - Maven
At the start of the project, we were compiling everything by hand (sounds worse than it
actually was) and we did not need any external dependencies (aside from [SQLite](#--sqlite)).
However, we wanted to use **Argon2** as a safe hashing solution, which comes as a Maven
dependency, so we migrated our project to maven. In the end, we could not make **Argon2** 
and its dependencies work (we opted for **PBKDF2**), but we still left maven in our project 
to allow for a more flexible compilation process.

## Client Commands
The client's interface provides multiple commands. Here we list the commands and their
proper arguments. A list of all commands can also be printed in our client application
by typing "help".

```
- login [username] [password] -> Logs [username] into the system.
- mkdir [username] [path] -> Creates a new directory [path].
- put [username] [path]/[file] -> Places the [file] in the [path].
- get [username] [path]/[file] -> Gets the [file] on the [path].
- ls [username] [path] -> Lists files or directories in [username]'s [path], on [username]'s home-root 
on the remote file repository.
- ls [username] -> Lists files or directories on [username]'s home-root on the remote file repository.
- cp [username] [path1]/[file1] [path2]/[file2] -> Copies [file1] in [path1] to [path2] as [file2].
- file [username] [path]/[file] -> Shows metadata for [file] in [path], showing its name, whether it's 
a file or directory, the type of file, creation date and last modification date.
- rm [username] [path]/[file] -> Removes/deletes [username]'s [file] in [path].
- help -> Prints a message to the console.
- exit -> Exits the application.
```

## Additional Notes

### - TLSv1.1
This [article](https://www.petefreitag.com/blog/tlsv1-tlsv1-1-disabled-java/#:~:text=1%20Disabled%20by%20Default%20in%20Java,-Updated%20on%20October&text=The%20OpenJDK%20Crypto%20Roadmap%20states,released%20after%20April%2020%2C%202021.)
is where we discovered we had to modify the _java.security_ file to make **TLSv1.1** work in our
project. We had to modify both our local jdk and amazon's jdk that we are using for our containers. More
notes about this can be found in the _Dockerfile_.

The modification we had to make was to move TLSv1.1 from the _jdk.tls.disabledAlgorithms_ to the
_jdk.tls.legacyAlgorithms_.

### - Configs Folder
Our configs folder has all .conf's that our project uses. Each of the three backend servers has one where
the symmetric keys they share with each other are stored, along with any private-symmetric keys used for
protecting sensitive data (like password hashes in the database).

### - Spring
In the beginning, we were trying to use a RESTful solution using Spring, but we could not figure out,
after many tries, how to make the certificates work, so we decided to go with traditional TLS Sockets
because those were already functional in the professor's examples from practical classes.

### - Buffer Size Limit
With this project, we also discovered that each OS has its own limit for TLS Buffer sizes. This project
has the hardcoded value for a macOS' max buffer size (16,383 bytes). This value is stored in the 
"_utils/CommonValues.java_" class and can be altered if your machine has more capacity. This will allow
to transfer bigger files (because we are not using a File Transfer Protocol).

## Authors
- Diogo Costa N.59893
- Tomás Gabriel N.60722
- Francisco Vasco N.61028
- Tomé Dias N.60719
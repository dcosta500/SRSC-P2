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
- [Interesting Links](#interesting-links)
- [Authors](#authors)

## How to compile and run
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
If the code is already compiled and the servers are already running, you can use the following command to run a client.

```
sh runC.sh [name]
```

This way, the users' files are preserved between sessions.

## Overview
This is the second project for SRSC-22/23. We developed a **Service Request Network**
where a user can **authenticate**, **request access** and **use** our developed servers and
their services. For this project, only a **File Managing Service** is available.

### - File Managing Service
In this service, each client has a folder of their own. For academic purposes, anyone with 
"_read and write_" permissions can put files in each other's folders, "_read_" permissions does
not let you write files, only read, and "_deny_" permission does not let you do any operations
of the service.

### - Clients
Our project has no registration feature, so we have created 5 pre-made clients for you to use.

- Alice - **uid**: alice, **pwd**: alice123456
- Bob - **uid**: bob, **pwd**: bob123456
- Carol - **uid**: carol, **pwd**: carol123456
- David - **uid**: david, **pwd**: david123456
- Eric - **uid**: eric, **pwd**: eric123456

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
All servers of our network are run in **Docker** containers and managed using
**Docker Compose**.

## Client Commands
The client's interface provides multiple commands. Here we list the commands and their
proper arguments.

```
- login [username] [password]
- TODO...
```

## Interesting Links

## Authors
- Diogo Costa N.59893
- Tomás Gabriel N.60722
- Francisco Vasco N.61028
- Tomé Dias N.60719
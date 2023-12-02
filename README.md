# SRSC-P2

## Overview
This is the second project for SRSC-22/23. We developed a **Service Request Network**
where a user can **authenticate**, **request access** and **use** our developed servers.

All servers of our network are run in **Docker** containers and managed using
**Docker Compose**.

## Architecture

Consider the following picture, the four nodes in the center and right side represent our
network of servers.

<img src="https://i.imgur.com/RK8gxO6.png" alt="Screenshot of the project's architecture." width="400"/>

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


- **Storage Service (S)**: TODO


## How to compile and run
### Compilation Script
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

### Run Client Script
If the servers are already running, you can use the following command to run a client.

```
sh runC.sh [name]
```

## Client Commands
The client's interface provides multiple commands. Here we list the commands and their
proper arguments.

- stats
- login [username] [password]
- access [service]

## Authors
- Diogo Costa N.59893
- Tomás Gabriel N.60722
- Francisco Vasco N.
- Tomé Dias N.
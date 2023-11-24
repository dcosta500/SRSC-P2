# SRSC-P2

## Briefing

Escrevo este briefing para o menino Tomé Dias, o amor da minha vida <3

Temos todas as bases do trabalho a funcionar, só falta o SQLite (fica a dica para começares a ver disso ;).

Limpei bastante o código, como te prometi. Podes explorar um bocado e ver que os métodos estão bastante mais
pequenos. Aprendi a fatorizar variáveis and shit para módulos acima, portanto conseguir refactorizar muita coisa.
Muitos métodos foram factorizados para o MySSLUtils.java, tornando SUUUUUPER fácil criar um client ou um server
(podes ver um exemplo do quao fácil é criar um client socket, por exemplo, no método login do MediaDispatcher.java,
onde o MediaDispatcher tem de redirecionar pedidos do cliente para o Authentication Server)

Neste momento temos 3 entidades a funcionar: Client, MediaDispatcher e AuthenticationServer. Os métodos SUM e MULT que
fizeste ainda estão cá e ainda estão a funcionar.

Fiz um novo método login que vou usar de base para o verdadeiro login, neste momento só manipula uma string.
O método faz duas round trips entre as 3 entidades. Vou ilustrar:

1. client -> mainDispatcher -> authServer
2. authServer -> mainDispatcher -> client
3. client -> mainDispatcher -> authServer
4. authServer -> mainDispatcher -> client

O fixe disto é que só usamos uma conexão, como tanto queriamos :D
Assim o client não tem de abrir uma conexão duas vezes com o mainDispatcher, que era como era necessário fazer no spring.
Podes tentar analisar o fluxo de código do login para perceberes mais ou menos como está tudo a funcionar.

## How To Run

To run the code first you will need to compile it. To do so, run the compileProject.sh script. Make sure you
are in the root folder of the project. The compilation script will also generate new keys. If you have already
created the keys in the certs/ folder just comment that out in the script.

Then to run each individual entity just run its respective script, again in the root folder of the project.
For example, to run the client, you need to execute the runClient.sh.

We recommend first opening other servers, then MainDispatcher and then the client.

## TODO

Create a .conf file with user name that creates all certificates accordingly

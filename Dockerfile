FROM openjdk:17

WORKDIR /app

COPY /out /app/

CMD ["java" ,"-cp" ,"out", "servers.MainDispatcher.MainDispatcherServer"]
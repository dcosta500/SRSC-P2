FROM openjdk:17

WORKDIR /app

COPY certs /app/certs
COPY db /app/db
COPY out /app/out
COPY src /app/src

EXPOSE 8080
CMD ["java" ,"-cp" ,"out", "servers.MainDispatcher.MainDispatcherServer"]
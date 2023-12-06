FROM amazoncorretto:17.0.7-alpine

WORKDIR /app
COPY out /app/out

# This line subtitutes the original java.security of our jdk for our own custom java.security.
# The only difference from the original is that it
COPY configs/java_security_custom /usr/lib/jvm/java-17-amazon-corretto/conf/security/java.security
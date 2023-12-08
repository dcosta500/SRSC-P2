FROM amazoncorretto:17.0.7-alpine

WORKDIR /app
COPY target /app/target

# This line subtitutes the original java.security of our jdk for our own custom java.security.
# The only difference from the original is that it removes TLSv1.1 from the disabled algorithms
# and adds it to the legacy algorithms to make it work in our project.
COPY configs/java_security_custom /usr/lib/jvm/java-17-amazon-corretto/conf/security/java.security
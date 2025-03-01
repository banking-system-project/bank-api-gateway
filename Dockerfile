FROM gradle:8.10.0-jdk17-alpine AS builder

RUN mkdir -p /app/source
COPY . /app/source

RUN gradle --version

WORKDIR /app/source
RUN gradle clean build

FROM eclipse-temurin:17.0.11_9-jre-alpine AS run
LABEL authors="prithwiraj"
COPY --from=builder /app/source/build/libs/*.jar /app/app.jar

EXPOSE 8070
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
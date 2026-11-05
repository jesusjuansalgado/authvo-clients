# INDIGO IAM built from a FORK, for the "native" configuration of the harness
# (docker-compose.fork.yml): the IAM itself publishes the RFC 8414 document and
# `protected_resources`, so the metadata augmenter is not needed.
#
# The fork adds, on top of upstream `develop` (v1.15.0):
#   RFC 8414 metadata, `protected_resources` (IAM + iam.protected-resources), RFC 9728
#   PRM for the IAM, repeated `resource` parameters -> every one in `aud`, optional
#   `invalid_target` for unlisted resources.
# Source: https://github.com/jesusjuansalgado/iam, branch rfc9728-protected-resource-metadata.
#
# The build pins a COMMIT, so the image is reproducible; change IAM_FORK_REF to test a newer one:
#   docker compose -f docker-compose.yml -f docker-compose.fork.yml build --build-arg IAM_FORK_REF=<sha-or-branch> iam
# It runs `mvn package -DskipTests` (the fork's own tests are its CI's job) and then lays the war out
# exactly as upstream's Dockerfile.prod does. Expect several minutes and ~1-2 GB of Maven downloads
# the first time (cached by Docker afterwards).

ARG IAM_FORK_REPO=https://github.com/jesusjuansalgado/iam.git
ARG IAM_FORK_REF=6e2225d712653b4d09b63f737fe2ee911216c0a1

FROM maven:3.9-eclipse-temurin-17 AS build
ARG IAM_FORK_REPO
ARG IAM_FORK_REF
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Fetch exactly one commit (works for a SHA or a branch/tag name); no submodules are needed.
RUN git init -q . && git remote add origin "$IAM_FORK_REPO" \
 && git fetch -q --depth 1 origin "$IAM_FORK_REF" && git checkout -q FETCH_HEAD \
 && git log -1 --format='building %H %s'
RUN mvn -B -ntp -q -pl iam-login-service -am package -DskipTests -Dmaven.javadoc.skip=true -Dlicense.skip=true \
 && ls -la iam-login-service/target/iam-login-service.war

FROM eclipse-temurin:17 AS layers
WORKDIR /indigo-iam
COPY --from=build /src/iam-login-service/target/iam-login-service.war /indigo-iam/
RUN java -Djarmode=layertools -jar iam-login-service.war extract

# Same runtime layout as upstream's iam-login-service/docker/Dockerfile.prod.
FROM eclipse-temurin:17
ARG IAM_FORK_REF
LABEL org.opencontainers.image.source="https://github.com/jesusjuansalgado/iam" \
      org.opencontainers.image.revision="$IAM_FORK_REF"
RUN mkdir /indigo-iam
WORKDIR /indigo-iam
COPY --from=layers indigo-iam/dependencies/ ./
COPY --from=layers indigo-iam/spring-boot-loader/ ./
COPY --from=layers indigo-iam/snapshot-dependencies/ ./
COPY --from=layers indigo-iam/application/ ./
RUN if [ -f WEB-INF/classes/keystore.jwks ]; then echo "ERROR: keystore.jwks in the image"; exit 1; fi
CMD ["/bin/sh", "-c", "java ${IAM_JAVA_OPTS} org.springframework.boot.loader.WarLauncher"]

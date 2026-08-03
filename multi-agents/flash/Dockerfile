# Stage-1 taint analysis backend. Builds a container carrying the analysis jar
# and run.sh; targets and their configs are mounted at run time.
#
#   docker build -t gadgethunter-flash .
#   docker run --rm -v /path/to/targets:/targets gadgethunter-flash --batch /targets
#
# See THIRD-PARTY-NOTICES.md at the repository root for the licenses of the
# components bundled in flash.jar.

FROM openjdk:17-jdk-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends procps \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /flash

COPY flash.jar run.sh ./

RUN chmod +x /flash/run.sh

ENTRYPOINT ["/flash/run.sh"]

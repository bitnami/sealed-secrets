FROM gcr.io/distroless/static@sha256:1a64f46364620465ef9e9a8f5413757dfdf22695e050bbfd7303eeaf17a59383
LABEL maintainer "Sealed Secrets <sealed-secrets.pdl@broadcom.com>"

USER 1001

ARG TARGETARCH
COPY dist/controller_linux_${TARGETARCH}*/controller /usr/local/bin/

EXPOSE 8080 8081

ENTRYPOINT ["controller"]

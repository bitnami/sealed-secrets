FROM gcr.io/distroless/static@sha256:4c2cd1dee442c9a99924a378c7c126fac8fef14771579ef567c3f2bdd7a5122a
LABEL maintainer "Sealed Secrets <sealed-secrets.pdl@broadcom.com>"

USER 1001

ARG TARGETARCH
COPY dist/kubeseal_linux_${TARGETARCH}*/kubeseal /usr/local/bin/

ENTRYPOINT ["kubeseal"]

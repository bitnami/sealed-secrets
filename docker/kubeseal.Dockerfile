FROM gcr.io/distroless/static@sha256:448810357cc8e67b7208988abdba0f5ec3d3aebee0a5b13eb624979792cffc0f
LABEL maintainer "Sealed Secrets <sealed-secrets.pdl@broadcom.com>"

USER 1001

ARG TARGETARCH
COPY dist/kubeseal_linux_${TARGETARCH}*/kubeseal /usr/local/bin/

ENTRYPOINT ["kubeseal"]

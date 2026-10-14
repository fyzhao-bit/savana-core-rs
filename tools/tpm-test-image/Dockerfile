FROM rust:1.82-bookworm
# Test-only simulator image. No application source, credentials or host TPM.
RUN apt-get update \
    && apt-get install -y --no-install-recommends swtpm tpm2-tools python3 \
    && apt-get clean \
    && rm -r /var/lib/apt/lists/*

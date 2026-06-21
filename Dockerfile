# syntax=docker/dockerfile:1.7

############################################
# Stage 1 — build the release binary
############################################
# Pinned to the MSRV (see Cargo.toml: rust-version = "1.88"). `bookworm` (not
# `slim`) so the image ships gcc + make, which `ring` needs for its build
# script. The builder's Debian major (12) is matched by the runtime stage so
# the dynamically-linked glibc lines up exactly.
FROM rust:1.88-bookworm AS builder

WORKDIR /src

# Copy the manifests + source. `.dockerignore` keeps `target/`, git history,
# local config (`*.ktav` — secrets), and editor cruft out of the context so
# the layer hash only changes on real source edits.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build the server binary only (`--bin resocks5`), skipping the library's
# examples and tests. `--locked` refuses to silently resolve versions above
# what the committed `Cargo.lock` pins — a CI drift turns into a hard error.
#
# The two cache mounts keep `cargo`'s registry + build artifacts across
# builds. The binary is `cp`'d out *within the same RUN* because the
# `/src/target` mount does not persist between layers.
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry \
    --mount=type=cache,target=/src/target,id=cargo-target \
    cargo build --release --locked --bin resocks5 && \
    cp target/release/resocks5 /resocks5

# An empty directory to be COPYed into the runtime stage as the working
# directory. We need it pre-existing in the builder because the runtime
# image is distroless and has no shell to run a `mkdir` / `chown`.
RUN mkdir -p /staging-cfg

############################################
# Stage 2 — minimal runtime
############################################
# `cc-debian12` (not `base`) includes glibc + libgcc + libstdc++, which `ring`
# links against. The `:nonroot` variant runs the process as UID 65532 by
# default. `webpki-roots` is compiled in, so no CA-certificates package is
# needed for outbound TLS.
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /resocks5 /usr/local/bin/resocks5
COPY LICENSE-MIT LICENSE-APACHE /licenses/

# resocks5 reads `resocks5.*.ktav` from its working directory and auto-creates
# them on first launch when missing. We COPY an empty directory from the
# builder with --chown=65532:65532 (the nonroot UID in distroless cc-debian12)
# so the runtime user can write its initial configs without EACCES. We can't
# `RUN mkdir` / `chown` here directly — distroless has no shell. A mounted
# volume overrides this; the chown only affects the image's empty default
# directory.
COPY --from=builder --chown=65532:65532 /staging-cfg /etc/resocks5
WORKDIR /etc/resocks5

# Default listen port (matches `resocks5.main.ktav` defaults).
EXPOSE 20082

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/resocks5"]

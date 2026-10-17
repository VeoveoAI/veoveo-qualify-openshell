# syntax=docker/dockerfile:1.27@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Qualification only: the accepted factory plus a bounded std-only test workload.
FROM factory AS build
USER root
COPY src/fixtures/lore_session.rs /tmp/lore_session.rs
RUN rustc --edition=2024 -O /tmp/lore_session.rs -o /usr/local/bin/vv-lore-session && rm /tmp/lore_session.rs
USER sandbox

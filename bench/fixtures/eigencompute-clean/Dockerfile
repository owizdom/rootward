# Base pinned by digest: on this platform the image digest IS the workload identity that
# KMS releases the wallet mnemonic to, so a floating tag makes the deployment
# unreproducible from source.
FROM node:22.11.0-slim@sha256:bd0c1d1cb8c14dc5d1b8ac8bb9a4a4e9c6d1f9e2b3a4c5d6e7f8091a2b3c4d5e

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY dist ./dist

# The platform entrypoint drops privileges after sourcing KMS-delivered secrets.
# Staying non-root keeps that mitigation intact.
USER node

EXPOSE 8080
CMD ["node", "dist/main.js"]

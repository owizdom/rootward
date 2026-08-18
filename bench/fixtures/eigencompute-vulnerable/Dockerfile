# Floating tag: the digest this builds to is not reproducible from source, and on this
# platform the digest is the identity KMS releases the wallet to.
FROM node:22-slim

WORKDIR /app
COPY package.json ./
RUN npm install

COPY dist ./dist

# Baked into the image, which every deploy pushes to a registry.
ENV ECLOUD_PRIVATE_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d

# EigenCloud TDX requirement: run as root
USER root

EXPOSE 3001
CMD ["node", "dist/main.js"]

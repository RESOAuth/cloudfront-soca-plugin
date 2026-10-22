FROM docker.io/library/node:24-bookworm-slim@sha256:2dd9a4f758e173b65fee15388f7706af6fb01ef50cf7a2c0538711d67a6981ae
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts && npm cache clean --force
COPY src/ ./src/
COPY generator/ ./generator/
COPY demo/ ./demo/
COPY tests/ ./tests/
COPY LICENSE ./LICENSE
USER node
EXPOSE 8443
CMD ["npm", "run", "demo"]

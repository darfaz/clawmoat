FROM node:20-alpine

# Set working directory
WORKDIR /app

# Install dependencies
COPY package.json ./
RUN npm install --omit=dev

# Copy source code
COPY . .

# Ensure CLI is executable
RUN chmod +x bin/clawmoat.js

# Environment variables
ENV NODE_ENV=production
ENV CLAWMOAT_POLICY=strict

# CLI entrypoint
ENTRYPOINT ["node", "bin/clawmoat.js"]


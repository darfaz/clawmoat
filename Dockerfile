FROM node:22-alpine AS base
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts 2>/dev/null || npm install --omit=dev --ignore-scripts
COPY . .

# Minimal image — just ClawMoat CLI
ENTRYPOINT ["node", "bin/clawmoat.js"]
CMD ["--help"]

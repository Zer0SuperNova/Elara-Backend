FROM node:22-alpine AS builder

RUN apk add --no-cache python3 make g++ bash libsodium-dev openssl-dev

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build


FROM node:22-alpine AS runtime

RUN apk add --no-cache libsodium openssl

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=builder /app/dist ./dist

EXPOSE 3000

CMD ["node", "dist/index.js"]
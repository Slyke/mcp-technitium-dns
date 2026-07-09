FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

ENV CONFIG_FILE=./data/config.json5
EXPOSE 3443

CMD ["node", "src/index.js"]

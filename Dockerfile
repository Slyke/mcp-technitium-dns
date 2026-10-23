FROM node:24-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

ENV CONFIG_FILE=./data/config.json5
EXPOSE 3443

CMD ["node", "src/index.js"]

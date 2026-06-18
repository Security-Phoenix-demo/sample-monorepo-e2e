FROM node:14-alpine
WORKDIR /app
# Running as root — insecure container
COPY package.json .
RUN npm install --no-audit
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]

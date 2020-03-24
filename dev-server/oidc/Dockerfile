FROM node:10

WORKDIR /app

RUN apt update && apt upgrade -qy

COPY package.json ./

RUN  rm -rf node_modules

RUN npm install -g npm@latest && \
    npm i camelcase oidc-provider

COPY . .

CMD [ "node", "server.js" ]

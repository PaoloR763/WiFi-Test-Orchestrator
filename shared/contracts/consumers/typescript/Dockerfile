FROM node:22.16.0-alpine3.22@sha256:41e4389f3d988d2ed55392df4db1420ad048ae53324a8e2b7c6d19508288107e
WORKDIR /consumer
COPY shared/contracts/consumers/typescript/package.json shared/contracts/consumers/typescript/package-lock.json ./
RUN npm ci
COPY shared/contracts/consumers/typescript/tsconfig.json ./
COPY shared/contracts/consumers/typescript/src ./src
COPY shared/contracts /contracts
ENV WTO_CONTRACT_ROOT=/contracts
CMD ["npm", "test"]

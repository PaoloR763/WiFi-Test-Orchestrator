FROM node:22.16.0-alpine3.22 AS tools

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .

FROM tools AS build
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.28.0-alpine3.21
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

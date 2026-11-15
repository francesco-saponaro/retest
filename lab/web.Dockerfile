# The web app built against the API (not the demo), served by nginx, which proxies /api to the API.
FROM node:22-slim AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY packages ./packages
COPY apps/api ./apps/api
COPY apps/web ./apps/web
RUN pnpm install --frozen-lockfile --filter "@retest/web..."
RUN pnpm -C apps/web build

FROM nginx:1.27-alpine
COPY lab/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/apps/web/dist /usr/share/nginx/html

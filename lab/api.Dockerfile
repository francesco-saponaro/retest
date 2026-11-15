# The API, with the command line next to it, so the lab needs nothing installed on the host but Docker.
FROM node:22-slim AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY packages ./packages
COPY apps/api ./apps/api
COPY apps/cli ./apps/cli
RUN pnpm install --frozen-lockfile --filter "@retest/api..." --filter "@retest/cli..."
RUN pnpm --filter "@retest/api..." --filter "@retest/cli..." run build

FROM node:22-slim
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=node:node /app /app
USER node
EXPOSE 3001
CMD ["node", "apps/api/dist/server.js"]

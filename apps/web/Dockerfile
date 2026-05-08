FROM node:22-alpine AS base
WORKDIR /app
COPY package.json tsconfig.base.json ./
COPY apps/web/package.json apps/web/package.json
COPY packages/shared/package.json packages/shared/package.json
RUN npm install
COPY apps/web apps/web
COPY packages/shared packages/shared
WORKDIR /app/apps/web
EXPOSE 3000
CMD ["npm", "run", "dev"]
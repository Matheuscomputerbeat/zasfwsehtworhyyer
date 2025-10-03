FROM node:20-bullseye
WORKDIR /srv
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev
COPY apps ./apps
COPY data ./data
ENV PORT=8080
EXPOSE 8080
CMD ["npm","start"]

# Node 20 minimal image
FROM node:20-alpine
WORKDIR /srv
COPY package.json ./
RUN npm install --omit=dev
COPY apps ./apps
COPY data ./data
ENV PORT=8080
EXPOSE 8080
CMD ["npm","start"]

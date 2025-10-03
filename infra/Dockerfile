# Node LTS (20) baseado em Debian, mais completo que alpine
FROM node:20-slim

# Diretório de trabalho
WORKDIR /srv

# Instala dependências do sistema
# - puppeteer precisa de libs de chromium (libnss3, fonts, etc)
# - better-sqlite3 precisa de build tools (python3, g++, make)
RUN apt-get update && apt-get install -y \
  python3 g++ make \
  libnss3 libatk-bridge2.0-0 libatk1.0-0 libx11-6 \
  libxcomposite1 libxdamage1 libxext6 libxfixes3 \
  libxrandr2 libgbm1 libasound2 libpangocairo-1.0-0 \
  libpango-1.0-0 libcairo2 fonts-liberation \
  && rm -rf /var/lib/apt/lists/*

# Copia package.json e instala dependências
COPY package.json ./
RUN npm install --omit=dev && npm rebuild better-sqlite3 --build-from-source

# Copia código
COPY apps ./apps
COPY data ./data

# Variáveis de ambiente
ENV PORT=8080
ENV PUPPETEER_SKIP_DOWNLOAD=true
EXPOSE 8080

# Start
CMD ["npm","start"]

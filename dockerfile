# Imagem Debian (glibc) evita dor de cabeça com sqlite3 nativo
FROM node:20-bookworm-slim

# Criar diretórios
WORKDIR /app

# Copiar package.json/package-lock (ou pnpm/yarn se usar)
COPY package*.json ./

# Instalar deps (só de produção)
RUN npm ci --omit=dev

# Copiar o restante do projeto
COPY . .

# Porta do app
EXPOSE 3000

# Variáveis default (podem ser sobrescritas por secrets)
ENV NODE_ENV=production \
    PORT=3000

# Start
CMD ["node", "server.mjs"]

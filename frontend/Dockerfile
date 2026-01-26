# Build stage
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
# Workaround for npm optional dependency bug on Alpine
RUN npm ci --prefer-offline || npm install
COPY . .
RUN npm run build

# Production stage
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

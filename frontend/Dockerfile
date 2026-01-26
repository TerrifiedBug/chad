# Build stage
FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
# Regenerate package-lock.json for Linux platform (fixes npm optional dependency bug)
RUN rm -f package-lock.json && npm install
COPY . .
RUN npm run build

# Production stage
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

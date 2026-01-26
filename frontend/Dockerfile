# Build stage
FROM node:20-slim AS build
WORKDIR /app

# Copy only dependency files first (cache-friendly)
COPY package.json package-lock.json ./

# Install deps for *this OS*
RUN npm ci

# Now copy the rest of the source
COPY . .

# Build
RUN npm run build

# Production stage
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

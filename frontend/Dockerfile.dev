FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy application code
COPY . .

# Expose dev server port
EXPOSE 3000

# Default command (overridden in docker-compose for dev)
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

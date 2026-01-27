#!/bin/bash
set -e

echo "Starting CHAD backend..."

# Run database migrations
# Note: PostgreSQL readiness is ensured by docker-compose depends_on healthcheck
echo "Running database migrations..."
alembic upgrade head

# Start the application
echo "Starting application server..."
exec "$@"

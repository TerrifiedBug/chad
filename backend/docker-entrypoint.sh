#!/bin/bash
set -e

echo "Starting CHAD backend..."

# Wait for PostgreSQL to be ready
if [ -n "$POSTGRES_HOST" ]; then
    echo "Waiting for PostgreSQL to be ready at $POSTGRES_HOST:$POSTGRES_PORT..."
    until PGPASSWORD=$POSTGRES_PASSWORD psql -h "$POSTGRES_HOST" -p "${POSTGRES_PORT:-5432}" -U "$POSTGRES_USER" -d postgres -c '\q' 2>/dev/null; do
        echo "PostgreSQL is unavailable - sleeping"
        sleep 1
    done
    echo "PostgreSQL is ready"
fi

# Run database migrations
echo "Running database migrations..."
alembic upgrade head

# Start the application
echo "Starting application server..."
exec "$@"

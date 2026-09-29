#!/usr/bin/env bash
# exit on error
set -o errexit

# 1. Install uv if it's not already in the environment
echo "Installing uv..."
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.cargo/env

# 2. Install dependencies using uv
# This is much faster than standard pip install
echo "Installing dependencies..."
uv pip install --system -r requirements.txt

# 3. Collect static files for WhiteNoise
echo "Collecting static files..."
python manage.py collectstatic --no-input

# 4. Run database migrations (MariaDB/MySQL via DATABASE_URL)
echo "Running migrations..."
python manage.py migrate

# 5. Optional: Run your custom setup script 
# (Uncomment the line below if you want to seed the DB on every deploy)
python manage.py setup_admin

echo "Build process completed successfully!"
#!/bin/bash

# Danger Auto Hitter Python Backend Server Setup Script
# This script sets up the Python backend server on an Ubuntu VPS

# Exit on error
set -e

echo "=== Danger Auto Hitter Python Backend Server Setup ==="
echo "This script will set up the Python Flask backend server on your Ubuntu VPS."
echo

# Check if running as root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# Update system
echo "Updating system packages..."
apt-get update
apt-get upgrade -y

# Install Python and pip
echo "Installing Python and dependencies..."
apt-get install -y python3 python3-pip python3-venv

# Install MongoDB
echo "Installing MongoDB..."
apt-get install -y gnupg
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/6.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-6.0.list
apt-get update
apt-get install -y mongodb-org

# Start MongoDB
echo "Starting MongoDB service..."
systemctl start mongod
systemctl enable mongod

# Install Supervisor for process management
echo "Installing Supervisor..."
apt-get install -y supervisor

# Create app directory
echo "Creating application directory..."
mkdir -p /opt/danger-auto-hitter
cd /opt/danger-auto-hitter

# Create virtual environment
echo "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Create .env file
echo "Creating .env file..."
cat > /opt/danger-auto-hitter/.env << EOL
# Server Configuration
PORT=3000

# MongoDB Configuration
MONGODB_URI=mongodb://localhost:27017/dangerAutoHitter

# JWT Secret
JWT_SECRET=danger_auto_hitter_secret

# Admin Configuration
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
ADMIN_EMAIL=admin@example.com
EOL

# Create supervisor config
echo "Creating supervisor configuration..."
cat > /etc/supervisor/conf.d/danger-auto-hitter.conf << EOL
[program:danger-auto-hitter]
directory=/opt/danger-auto-hitter
command=/opt/danger-auto-hitter/venv/bin/gunicorn -w 4 -b 0.0.0.0:3000 server:app
autostart=true
autorestart=true
stderr_logfile=/var/log/danger-auto-hitter.err.log
stdout_logfile=/var/log/danger-auto-hitter.out.log
user=root
environment=PYTHONPATH="/opt/danger-auto-hitter"
EOL

echo
echo "=== Setup Complete ==="
echo "Your Python Flask backend server is now set up!"
echo "MongoDB is running on the default port (27017)"
echo "The API server will run on port 3000 by default"
echo
echo "Important: Make sure to update the .env file with secure credentials"
echo "Location: /opt/danger-auto-hitter/.env"
echo
echo "To complete the setup, copy your server.py and requirements.txt to /opt/danger-auto-hitter/"
echo "Then run the following commands:"
echo "cd /opt/danger-auto-hitter"
echo "source venv/bin/activate"
echo "pip install -r requirements.txt"
echo "supervisorctl reread"
echo "supervisorctl update"
echo "supervisorctl start danger-auto-hitter"
echo
echo "To configure your extension, use the following backend URL:"
echo "http://YOUR_SERVER_IP:3000/api"
echo
echo "Don't forget to open port 3000 in your firewall if needed:"
echo "ufw allow 3000/tcp"
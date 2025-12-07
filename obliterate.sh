#!/bin/bash
# obliterate.sh - Complete server cleanup

echo "=== OBLITERATING EVERYTHING ==="

# Stop all containers
echo "Stopping all containers..."
docker stop $(docker ps -aq) 2>/dev/null || true

# Remove all containers
echo "Removing all containers..."
docker rm $(docker ps -aq) 2>/dev/null || true

# Remove all volumes
echo "Removing all volumes..."
docker volume rm $(docker volume ls -q) 2>/dev/null || true

# Remove all custom networks
echo "Removing all custom networks..."
docker network rm $(docker network ls --filter type=custom -q) 2>/dev/null || true

# Remove all images
echo "Removing all images..."
docker rmi $(docker images -q) 2>/dev/null || true

# Clean up directories
echo "Removing application directories..."
rm -rf /home/n8n /home/supabase /home/node-exporter /home/cadvisor /home/vibe-apps /home/prometheus /home/grafana

# Remove Docker daemon config
echo "Removing Docker daemon config..."
rm -f /etc/docker/daemon.json

# Reset PostgreSQL
echo "Resetting PostgreSQL..."
sudo -u postgres psql -c "DROP DATABASE IF EXISTS n8n_db;" 2>/dev/null || true
sudo -u postgres psql -c "DROP USER IF EXISTS n8n_user;" 2>/dev/null || true

# Restart Docker
echo "Restarting Docker..."
systemctl restart docker

# Verify clean state
echo ""
echo "=== VERIFICATION ==="
echo "Docker containers:"
docker ps -a
echo ""
echo "Docker volumes:"
docker volume ls
echo ""
echo "Docker networks:"
docker network ls
echo ""
echo "Home directories:"
ls -la /home/ | grep -E "n8n|supabase|cadvisor|node-exporter|vibe|prometheus|grafana" || echo "No application directories found"
echo ""
echo "=== OBLITERATION COMPLETE ==="

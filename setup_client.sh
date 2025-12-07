#!/bin/bash
#
# Bit Creative - Client Server Setup Script
# Version: 2.1
# Author: Adam Fox & eVA
# Description: This script automates the setup of a new client server with
#              n8n, Supabase, Caddy, monitoring (Prometheus, Grafana, node-exporter, cAdvisor),
#              and vibe-apps, using a standardized template repository.
#
# --- Configuration ---
set -e # Exit immediately if a command exits with a non-zero status.
readonly VIBE_APPS_REPO="https://github.com/adam3456223/vibe.git"
readonly CLIENT_CONFIG_FILE="client_vars.env"
readonly LOG_FILE="setup_$(date +%Y-%m-%d_%H-%M-%S).log"
# --- Logging Function ---
log() {
    echo "$@" | tee -a "$LOG_FILE"
}
# --- JWT Generation Function ---
generate_jwt() {
    local payload="$1"
    local secret="$2"
    local header='{"alg":"HS256","typ":"JWT"}'
    local b64_header=$(echo -n "$header" | base64 | tr -d '=' | tr '/+' '_-')
    local b64_payload=$(echo -n "$payload" | base64 | tr -d '=' | tr '/+' '_-')
    local unsigned_token="${b64_header}.${b64_payload}"
    local signature=$(echo -n "$unsigned_token" | openssl dgst -sha256 -hmac "$secret" -binary | base64 | tr -d '=' | tr '/+' '_-')
    echo "${unsigned_token}.${signature}"
}
# --- Script Phases ---
preflight_checks() {
    log "### Phase 1: Running Pre-flight Checks ###"
    if [ "$EUID" -ne 0 ]; then log "ERROR: This script must be run as root."; exit 1; fi
    for cmd in docker git ufw openssl curl; do
        if ! command -v "$cmd" &> /dev/null; then log "ERROR: Required command '$cmd' is not installed."; exit 1; fi
    done
    if ! docker compose version &> /dev/null; then log "ERROR: Docker Compose V2 plugin is not installed."; exit 1; fi
    log "--> Pre-flight checks passed."
}
get_user_config() {
    log "### Phase 2: Gathering Configuration ###"
    local config_is_valid=false
    if [ -f "$CLIENT_CONFIG_FILE" ]; then
        log "--> Found existing config file '$CLIENT_CONFIG_FILE'. Validating..."
        source "$CLIENT_CONFIG_FILE"
        required_vars=(
            "N8N_DOMAIN_NAME" "NETWORK_NAME" "SUPABASE_DOMAIN" "SSL_EMAIL" "SERVER_PUBLIC_IP" "LOGGING_SERVER_IP"
            "GENERIC_TIMEZONE" "N8N_DB_PASSWORD" "SUBDOMAIN" "SUPABASE_POSTGRES_PASSWORD" "JWT_SECRET" "ANON_KEY" "SERVICE_ROLE_KEY"
            "DASHBOARD_USERNAME" "DASHBOARD_PASSWORD" "SECRET_KEY_BASE" "VAULT_ENC_KEY" "VIBE_DOMAIN" "FUNCTIONS_DOMAIN"
            "PROMETHEUS_DOMAIN" "GRAFANA_DOMAIN" "GRAFANA_ADMIN_PASSWORD" "GITHUB_TOKEN"
        )
        config_is_valid=true
        for var_name in "${required_vars[@]}"; do
            if [ -z "${!var_name}" ]; then
                log "--> WARNING: Variable '$var_name' is missing from config file. Re-prompting for all values."
                config_is_valid=false
                break
            fi
        done
    fi
    if [ "$config_is_valid" = false ]; then
        log "--> No valid config file found. Prompting for new values..."
        
        # Auto-detect server IP
        SERVER_PUBLIC_IP=$(curl -s ifconfig.me)
        log "--> Detected server public IP: $SERVER_PUBLIC_IP"
        
        # Hardcode logging server IP
        LOGGING_SERVER_IP="68.183.29.60"
        
        read -p "Enter the client's main domain name (e.g., client.com): " N8N_DOMAIN_NAME
        read -p "Enter the subdomain for n8n (e.g., n8n): " SUBDOMAIN
        read -p "Enter the subdomain for Supabase (e.g., supabase): " SUPABASE_SUBDOMAIN
        read -p "Enter the subdomain for vibe-apps (e.g., vibe): " VIBE_SUBDOMAIN
        read -p "Enter the subdomain for functions (e.g., functions): " FUNCTIONS_SUBDOMAIN
        read -p "Enter the subdomain for Prometheus (e.g., prometheus): " PROMETHEUS_SUBDOMAIN
        read -p "Enter the subdomain for Grafana (e.g., grafana): " GRAFANA_SUBDOMAIN
        
        # Build full domains
        SUPABASE_DOMAIN="${SUPABASE_SUBDOMAIN}.${N8N_DOMAIN_NAME}"
        VIBE_DOMAIN="${VIBE_SUBDOMAIN}.${N8N_DOMAIN_NAME}"
        FUNCTIONS_DOMAIN="${FUNCTIONS_SUBDOMAIN}.${N8N_DOMAIN_NAME}"
        PROMETHEUS_DOMAIN="${PROMETHEUS_SUBDOMAIN}.${N8N_DOMAIN_NAME}"
        GRAFANA_DOMAIN="${GRAFANA_SUBDOMAIN}.${N8N_DOMAIN_NAME}"
        
        read -p "Enter the desired timezone (e.g., Australia/Melbourne): " GENERIC_TIMEZONE
        read -sp "Enter the password for the n8n database user: " N8N_DB_PASSWORD; echo
        read -p "Enter the SSL contact email: " SSL_EMAIL
        read -p "Enter the desired username for the Supabase dashboard admin: " DASHBOARD_USERNAME; echo
        read -sp "Enter the desired password for the Supabase dashboard admin: " DASHBOARD_PASSWORD; echo
        read -sp "Enter the desired password for Grafana admin: " GRAFANA_ADMIN_PASSWORD; echo
        read -p "Enter the desired Docker network name (e.g., bitcreative): " NETWORK_NAME
        read -p "Enter GitHub Personal Access Token (for private repos): " GITHUB_TOKEN
        
        log "--> Prompting for API keys (leave blank to skip)..."
        read -p "Enter OpenAI API key (or press Enter to skip): " OPENAI_API_KEY
        read -p "Enter Gemini API key (or press Enter to skip): " GEMINI_API_KEY
        read -p "Enter Anthropic API key (or press Enter to skip): " ANTHROPIC_API_KEY
        
        log "--> Auto-generating required secrets..."
        SUPABASE_POSTGRES_PASSWORD=$(openssl rand -hex 32)
        JWT_SECRET=$(openssl rand -hex 32)
        SECRET_KEY_BASE=$(openssl rand -hex 64)
        VAULT_ENC_KEY=$(openssl rand -hex 32)
        GRAFANA_RENDERING_TOKEN=$(openssl rand -hex 32)
        
        log "--> Generating Supabase JWT keys..."
        ANON_KEY=$(generate_jwt '{"role":"anon"}' "$JWT_SECRET")
        SERVICE_ROLE_KEY=$(generate_jwt '{"role":"service_role"}' "$JWT_SECRET")
        log "--> Saving configuration to '$CLIENT_CONFIG_FILE' for future use."
        cat > "$CLIENT_CONFIG_FILE" << EOL
# Client Server Configuration
N8N_DOMAIN_NAME="${N8N_DOMAIN_NAME}"
SUBDOMAIN="${SUBDOMAIN}"
NETWORK_NAME="${NETWORK_NAME}"
SUPABASE_DOMAIN="${SUPABASE_DOMAIN}"
VIBE_DOMAIN="${VIBE_DOMAIN}"
FUNCTIONS_DOMAIN="${FUNCTIONS_DOMAIN}"
PROMETHEUS_DOMAIN="${PROMETHEUS_DOMAIN}"
GRAFANA_DOMAIN="${GRAFANA_DOMAIN}"
SSL_EMAIL="${SSL_EMAIL}"
SERVER_PUBLIC_IP="${SERVER_PUBLIC_IP}"
LOGGING_SERVER_IP="${LOGGING_SERVER_IP}"
GENERIC_TIMEZONE="${GENERIC_TIMEZONE}"
N8N_DB_PASSWORD="${N8N_DB_PASSWORD}"
SUPABASE_POSTGRES_PASSWORD="${SUPABASE_POSTGRES_PASSWORD}"
JWT_SECRET="${JWT_SECRET}"
ANON_KEY="${ANON_KEY}"
SERVICE_ROLE_KEY="${SERVICE_ROLE_KEY}"
DASHBOARD_USERNAME="${DASHBOARD_USERNAME}"
DASHBOARD_PASSWORD="${DASHBOARD_PASSWORD}"
GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD}"
GRAFANA_RENDERING_TOKEN="${GRAFANA_RENDERING_TOKEN}"
SECRET_KEY_BASE="${SECRET_KEY_BASE}"
VAULT_ENC_KEY="${VAULT_ENC_KEY}"
OPENAI_API_KEY="${OPENAI_API_KEY}"
GEMINI_API_KEY="${GEMINI_API_KEY}"
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}"
GITHUB_TOKEN="${GITHUB_TOKEN}"
EOL
    fi
    log "--> Configuration loaded."
}
system_prep() {
    log "### Phase 3: Preparing System & Server ###"
    log "--> Applying kernel performance tuning..."
    if ! grep -q "vm.swappiness=10" /etc/sysctl.conf; then
        cat <<EOL >> /etc/sysctl.conf
vm.swappiness=10
net.core.somaxconn=1024
EOL
        sysctl -p
    else
        log "--> Kernel tuning already applied. Skipping."
    fi
    
    if ! grep -q "/swapfile" /etc/fstab; then
        log "--> Creating and enabling 4GB swap file..."
        fallocate -l 4G /swapfile; chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile
        echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
    else
        log "--> Swap file already exists. Skipping."
    fi
    
    log "--> Installing required packages..."
    apt-get update
    apt-get install -y postgresql postgresql-contrib net-tools apache2-utils
    
    log "--> Configuring Docker daemon for metrics and logging..."
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json << EOL
{
  "metrics-addr": "0.0.0.0:9323",
  "experimental": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOL
    
    log "--> System preparation complete."
}
setup_docker_env() {
    log "### Phase 4: Setting up Docker Environment ###"
    if ! docker network ls | grep -q "$NETWORK_NAME"; then
        log "--> Creating external Docker network: $NETWORK_NAME"
        docker network create "$NETWORK_NAME"
    else
        log "--> Docker network '$NETWORK_NAME' already exists. Skipping."
    fi
    for volume in caddy_data n8n_data grafana_data prometheus_data; do
        if ! docker volume ls | grep -q "$volume"; then
            log "--> Creating external Docker volume: $volume"
            docker volume create "$volume"
        else
            log "--> Docker volume '$volume' already exists. Skipping."
        fi
    done
    log "--> Docker environment setup complete."
}
setup_files() {
    log "### Phase 5: Setting up Configuration Files ###"
    local temp_dir="/root/server_setup"
    
    log "--> Creating destination directories..."
    mkdir -p /home/n8n /home/node-exporter /home/cadvisor /home/vibe-apps /home/prometheus/config /home/grafana/plugins
    
    log "--> Copying and renaming template files..."
    cp "$temp_dir"/n8n_.env /home/n8n/.env
    cp "$temp_dir"/n8n_Dockerfile /home/n8n/Dockerfile
    cp "$temp_dir"/n8n_docker-compose.yml /home/n8n/docker-compose.yml
    cp "$temp_dir"/Caddyfile /home/n8n/Caddyfile
    cp "$temp_dir"/node-exporter_docker-compose.yml /home/node-exporter/docker-compose.yml
    cp "$temp_dir"/cadvisor_docker-compose.yml /home/cadvisor/docker-compose.yml
    cp "$temp_dir"/prometheus_docker-compose.yml /home/prometheus/docker-compose.yml
    cp "$temp_dir"/prometheus.yml /home/prometheus/config/prometheus.yml
    cp "$temp_dir"/grafana_docker-compose.yml /home/grafana/docker-compose.yml
    
    log "--> Setting up Supabase from official repository..."
    cd /tmp
    rm -rf /tmp/supabase
    git clone --depth 1 https://github.com/supabase/supabase
    
    mkdir -p /home/supabase/docker
    cp -rf /tmp/supabase/docker/* /home/supabase/docker/
    cp /tmp/supabase/docker/.env.example /home/supabase/docker/.env
    
    log "--> Configuring Supabase .env with client values..."
    sed -i "s|POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${SUPABASE_POSTGRES_PASSWORD}|" /home/supabase/docker/.env
    sed -i "s|JWT_SECRET=.*|JWT_SECRET=${JWT_SECRET}|" /home/supabase/docker/.env
    sed -i "s|ANON_KEY=.*|ANON_KEY=${ANON_KEY}|" /home/supabase/docker/.env
    sed -i "s|SERVICE_ROLE_KEY=.*|SERVICE_ROLE_KEY=${SERVICE_ROLE_KEY}|" /home/supabase/docker/.env
    sed -i "s|DASHBOARD_USERNAME=.*|DASHBOARD_USERNAME=${DASHBOARD_USERNAME}|" /home/supabase/docker/.env
    sed -i "s|DASHBOARD_PASSWORD=.*|DASHBOARD_PASSWORD=${DASHBOARD_PASSWORD}|" /home/supabase/docker/.env
    sed -i "s|SECRET_KEY_BASE=.*|SECRET_KEY_BASE=${SECRET_KEY_BASE}|" /home/supabase/docker/.env
    sed -i "s|VAULT_ENC_KEY=.*|VAULT_ENC_KEY=${VAULT_ENC_KEY}|" /home/supabase/docker/.env
    sed -i "s|SITE_URL=.*|SITE_URL=https://${SUPABASE_DOMAIN}|" /home/supabase/docker/.env
    sed -i "s|SUPABASE_PUBLIC_URL=.*|SUPABASE_PUBLIC_URL=https://${SUPABASE_DOMAIN}|" /home/supabase/docker/.env
    
    log "--> Adding API keys to Supabase .env..."
    cat >> /home/supabase/docker/.env << EOL

# API Keys
OPENAI_API_KEY=${OPENAI_API_KEY}
GEMINI_API_KEY=${GEMINI_API_KEY}
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
EOL
    
    log "--> Updating Supabase docker-compose.yml network..."
    sed -i "s|default:|${NETWORK_NAME}:|g" /home/supabase/docker/docker-compose.yml
    sed -i "s|name: .*|name: ${NETWORK_NAME}|g" /home/supabase/docker/docker-compose.yml
    
    log "--> Cloning Supabase edge functions repository..."
    mkdir -p /home/supabase/docker/volumes
    if [ -d "/home/supabase/docker/volumes/functions" ]; then
        log "--> Functions directory already exists. Skipping clone."
    else
        git clone "https://adam3456223:${GITHUB_TOKEN}@github.com/adam3456223/supabase-functions.git" /home/supabase/docker/volumes/functions
    fi
    
    log "--> Cleaning up Supabase temp directory..."
    rm -rf /tmp/supabase
    
    log "--> Cloning vibe-apps repository..."
    if [ -d "/home/vibe-apps/vibe" ]; then
        log "--> Vibe-apps directory already exists. Skipping clone."
    else
        git clone "$VIBE_APPS_REPO" /home/vibe-apps/vibe
    fi
    
    log "--> Overwriting vibe-apps files with templates..."
    cp "$temp_dir"/vibe-apps_docker-compose.yml /home/vibe-apps/vibe/docker-compose.yml
    cp "$temp_dir"/vibe-apps_vite.config.js /home/vibe-apps/vibe/vite.config.js
    
    log "--> Configuring vibe-apps template files..."
    sed -i "s|{{VIBE_DOMAIN}}|${VIBE_DOMAIN}|g" /home/vibe-apps/vibe/vite.config.js
    sed -i "s|{{VIBE_DOMAIN}}|${VIBE_DOMAIN}|g" /home/vibe-apps/vibe/docker-compose.yml
    sed -i "s|{{NETWORK}}|${NETWORK_NAME}|g" /home/vibe-apps/vibe/docker-compose.yml
    log "--> Creating vibe-apps .env file..."
    cat > /home/vibe-apps/.env << EOL
PUBLIC_SUPABASE_URL=https://${SUPABASE_DOMAIN}
PUBLIC_SUPABASE_ANON_KEY=${ANON_KEY}
EOL
    log "--> Configuring copied files with client variables..."
    # Process n8n files
    sed -i "s|{{N8N_DOMAIN_NAME}}|${N8N_DOMAIN_NAME}|g" /home/n8n/.env
    sed -i "s|{{SUBDOMAIN}}|${SUBDOMAIN}|g" /home/n8n/.env
    sed -i "s|{{SSL_EMAIL}}|${SSL_EMAIL}|g" /home/n8n/.env
    sed -i "s|{{YOUR_DROPLET_IP}}|${SERVER_PUBLIC_IP}|g" /home/n8n/.env
    sed -i "s|{{N8N_DB_PASSWORD}}|${N8N_DB_PASSWORD}|g" /home/n8n/.env
    sed -i "s|{{GENERIC_TIMEZONE}}|${GENERIC_TIMEZONE}|g" /home/n8n/.env
    sed -i "s|{{NETWORK}}|${NETWORK_NAME}|g" /home/n8n/docker-compose.yml
    sed -i "s|{{SUBDOMAIN}}|${SUBDOMAIN}|g" /home/n8n/Caddyfile
    sed -i "s|{{N8N_DOMAIN_NAME}}|${N8N_DOMAIN_NAME}|g" /home/n8n/Caddyfile
    sed -i "s|{{SUPABASE_DOMAIN}}|${SUPABASE_DOMAIN}|g" /home/n8n/Caddyfile
    sed -i "s|{{VIBE_DOMAIN}}|${VIBE_DOMAIN}|g" /home/n8n/Caddyfile
    sed -i "s|{{FUNCTIONS_DOMAIN}}|${FUNCTIONS_DOMAIN}|g" /home/n8n/Caddyfile
    sed -i "s|{{PROMETHEUS_DOMAIN}}|${PROMETHEUS_DOMAIN}|g" /home/n8n/Caddyfile
    sed -i "s|{{GRAFANA_DOMAIN}}|${GRAFANA_DOMAIN}|g" /home/n8n/Caddyfile
    sed -i "s|{{LOGGING_SERVER_IP}}|${LOGGING_SERVER_IP}|g" /home/n8n/Caddyfile
    
    # Process monitoring files
    sed -i "s|{{NETWORK}}|${NETWORK_NAME}|g" /home/node-exporter/docker-compose.yml
    sed -i "s|{{NETWORK}}|${NETWORK_NAME}|g" /home/cadvisor/docker-compose.yml
    sed -i "s|{{NETWORK}}|${NETWORK_NAME}|g" /home/prometheus/docker-compose.yml
    sed -i "s|{{NETWORK}}|${NETWORK_NAME}|g" /home/grafana/docker-compose.yml
    
    # Process Prometheus config
    sed -i "s|{{SUBDOMAIN}}|${SUBDOMAIN}|g" /home/prometheus/config/prometheus.yml
    sed -i "s|{{N8N_DOMAIN_NAME}}|${N8N_DOMAIN_NAME}|g" /home/prometheus/config/prometheus.yml
    
    # Process Grafana config
    sed -i "s|{{GRAFANA_DOMAIN}}|${GRAFANA_DOMAIN}|g" /home/grafana/docker-compose.yml
    sed -i "s|{{GRAFANA_ADMIN_PASSWORD}}|${GRAFANA_ADMIN_PASSWORD}|g" /home/grafana/docker-compose.yml
    sed -i "s|{{GRAFANA_RENDERING_TOKEN}}|${GRAFANA_RENDERING_TOKEN}|g" /home/grafana/docker-compose.yml
    sed -i "s|{{NETWORK}}|${NETWORK_NAME}|g" /home/grafana/docker-compose.yml
    
    log "--> Cleaning up temporary directory..."
    rm -rf "$temp_dir"
    log "--> File setup complete."
}
setup_host_postgres() {
    log "### Phase 6: Setting up Host PostgreSQL for n8n ###"
    log "--> Configuring PostgreSQL to listen on all interfaces..."
    sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" /etc/postgresql/14/main/postgresql.conf
    log "--> Allowing MD5 password authentication from Docker network..."
    if ! grep -q "172.16.0.0/12" /etc/postgresql/14/main/pg_hba.conf; then
        echo "host    all             all             172.16.0.0/12           md5" >> /etc/postgresql/14/main/pg_hba.conf
    fi
    log "--> Restarting PostgreSQL service..."
    systemctl restart postgresql
    log "--> Creating n8n database and user..."
    if sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='n8n_user'" | grep -q 1; then
        log "--> User 'n8n_user' already exists."
    else
        sudo -u postgres psql -c "CREATE USER n8n_user WITH PASSWORD '$N8N_DB_PASSWORD';"
    fi
    if sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw n8n_db; then
        log "--> Database 'n8n_db' already exists."
    else
        sudo -u postgres psql -c "CREATE DATABASE n8n_db;"
        sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE n8n_db TO n8n_user;"
    fi
    log "--> PostgreSQL setup complete."
}
deploy_services() {
    log "### Phase 7: Deploying Docker Services ###"
    log "--> Starting n8n and Caddy services..."
    cd /home/n8n && docker compose up -d
    log "--> Starting Supabase services..."
    cd /home/supabase/docker && docker compose up -d
    log "--> Starting node-exporter..."
    cd /home/node-exporter && docker compose up -d
    log "--> Starting cAdvisor..."
    cd /home/cadvisor && docker compose up -d
    log "--> Starting Prometheus..."
    cd /home/prometheus && docker compose up -d
    log "--> Starting Grafana..."
    cd /home/grafana && docker compose up -d
    log "--> Starting vibe-apps..."
    cd /home/vibe-apps/vibe && docker compose up -d
    log "--> Configuring firewall..."
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 5432/tcp
    ufw allow from "$LOGGING_SERVER_IP" to any port 9100 proto tcp
    ufw allow from "$LOGGING_SERVER_IP" to any port 8080 proto tcp
    ufw allow from "$LOGGING_SERVER_IP" to any port 9323 proto tcp
    ufw allow from "$LOGGING_SERVER_IP" to any port 9187 proto tcp
    ufw allow from "$LOGGING_SERVER_IP" to any port 9090 proto tcp
    ufw --force enable
    log "--> Restarting Docker to apply daemon configuration..."
    systemctl restart docker
    log "--> Restarting all services after Docker restart..."
    cd /home/n8n && docker compose up -d
    cd /home/supabase/docker && docker compose up -d
    cd /home/node-exporter && docker compose up -d
    cd /home/cadvisor && docker compose up -d
    cd /home/prometheus && docker compose up -d
    cd /home/grafana && docker compose up -d
    cd /home/vibe-apps/vibe && docker compose up -d
    log "--> Service deployment complete."
}
# --- Main Execution Logic ---
main() {
    preflight_checks
    get_user_config
    system_prep
    setup_docker_env
    setup_files
    setup_host_postgres
    deploy_services
    log "--- ✅ SETUP COMPLETE ---"
    log ""
    log "Please save the following generated credentials in a secure location:"
    log "--------------------------------------------------"
    source "$CLIENT_CONFIG_FILE"
    log "n8n Database Password:      $N8N_DB_PASSWORD"
    log "Supabase Dashboard User:    $DASHBOARD_USERNAME"
    log "Supabase Dashboard Pass:    $DASHBOARD_PASSWORD"
    log "Supabase Postgres Pass:     $SUPABASE_POSTGRES_PASSWORD"
    log "Supabase JWT Secret:        $JWT_SECRET"
    log "Supabase Anon Key:          $ANON_KEY"
    log "Supabase Service Role Key:  $SERVICE_ROLE_KEY"
    log "Grafana Admin Password:     $GRAFANA_ADMIN_PASSWORD"
    log "--------------------------------------------------"
    log ""
    log "Your services should be available shortly at:"
    log "n8n:                https://${SUBDOMAIN}.${N8N_DOMAIN_NAME}"
    log "n8n metrics:        https://${SUBDOMAIN}.${N8N_DOMAIN_NAME}/metrics (restricted to ${LOGGING_SERVER_IP})"
    log "Supabase:           https://${SUPABASE_DOMAIN}"
    log "Vibe Apps:          https://${VIBE_DOMAIN}"
    log "Edge Functions:     https://${FUNCTIONS_DOMAIN}"
    log "Prometheus:         https://${PROMETHEUS_DOMAIN}"
    log "Grafana:            https://${GRAFANA_DOMAIN}"
    log ""
    log "Monitoring endpoints (accessible from ${LOGGING_SERVER_IP}):"
    log "node-exporter:      ${SERVER_PUBLIC_IP}:9100"
    log "cAdvisor:           ${SERVER_PUBLIC_IP}:8080"
    log "Docker metrics:     ${SERVER_PUBLIC_IP}:9323"
    log "Postgres exporter:  ${SERVER_PUBLIC_IP}:9187"
    log "Prometheus:         ${SERVER_PUBLIC_IP}:9090"
    log ""
    log "MANUAL NEXT STEPS:"
    log "1. Log in to the n8n UI and configure all necessary credentials."
    log "2. Install any required n8n community nodes."
    log "3. Configure your Prometheus server to scrape this client's metrics."
    log "4. If you skipped API keys, add them to /home/supabase/docker/.env and restart services."
    log "5. Verify all services are running correctly with 'docker ps -a'."
    log "6. Log in to Grafana and configure Prometheus as a data source."
    log ""
    log "A full log of this session has been saved to: $LOG_FILE"
}
# Pipe all output of the main function to the log file and stdout
main 2>&1 | tee -a "$LOG_FILE"

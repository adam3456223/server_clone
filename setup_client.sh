#!/bin/bash

#
# Bit Creative - Client Server Setup Script
# Version: 2.0
# Author: Adam Fox & eVA
# Description: This script automates the setup of a new client server with
#              n8n, Supabase, Caddy, monitoring (node-exporter, cAdvisor),
#              and vibe-apps, using a standardized template repository.
#

# --- Configuration ---
set -e # Exit immediately if a command exits with a non-zero status.
readonly TEMPLATE_REPO="https://bit_creative@bitbucket.org/bit_creative/docker.git"
readonly SUPABASE_FUNCTIONS_REPO="https://github.com/adam3456223/supabase-functions.git"
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
    for cmd in docker git ufw openssl; do
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
            "OPENAI_API_KEY" "GEMINI_API_KEY" "ANTHROPIC_API_KEY" "N8N_PRE_PROCESS_WEBHOOK_URL" "N8N_POST_PROCESS_WEBHOOK_URL"
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
        read -p "Enter this server's public IP address: " SERVER_PUBLIC_IP
        read -p "Enter the logging/monitoring server's IP address: " LOGGING_SERVER_IP
        read -p "Enter the client's main domain name for n8n (e.g., client.com): " N8N_DOMAIN_NAME
        read -p "Enter the subdomain for the n8n instance: " SUBDOMAIN; echo
        read -p "Enter the desired timezone (e.g., Australia/Melbourne): " GENERIC_TIMEZONE
        read -sp "Enter the password for the n8n database user: " N8N_DB_PASSWORD; echo
        read -p "Enter the Supabase full domain (including subdomain) but without https:// (e.g., supabase.client.com): " SUPABASE_DOMAIN
        read -p "Enter the vibe-apps full domain but without https:// (e.g., vibe.client.com): " VIBE_DOMAIN
        read -p "Enter the Supabase functions full domain but without https:// (e.g., functions.client.com): " FUNCTIONS_DOMAIN
        read -p "Enter the SSL contact email: " SSL_EMAIL
        read -p "Enter the desired username for the Supabase dashboard admin: " DASHBOARD_USERNAME; echo
        read -sp "Enter the desired password for the Supabase dashboard admin: " DASHBOARD_PASSWORD; echo
        read -p "Enter the desired Docker network name (e.g., bitcreative): " NETWORK_NAME

        log "--> Prompting for API keys (leave blank to skip)..."
        read -p "Enter OpenAI API key (or press Enter to skip): " OPENAI_API_KEY
        read -p "Enter Gemini API key (or press Enter to skip): " GEMINI_API_KEY
        read -p "Enter Anthropic API key (or press Enter to skip): " ANTHROPIC_API_KEY
        
        log "--> Prompting for n8n webhook URLs (leave blank to configure later)..."
        read -p "Enter n8n pre-process webhook URL (or press Enter to skip): " N8N_PRE_PROCESS_WEBHOOK_URL
        read -p "Enter n8n post-process webhook URL (or press Enter to skip): " N8N_POST_PROCESS_WEBHOOK_URL

        log "--> Auto-generating required secrets..."
        SUPABASE_POSTGRES_PASSWORD=$(openssl rand -hex 32)
        JWT_SECRET=$(openssl rand -hex 32)
        SECRET_KEY_BASE=$(openssl rand -hex 64)
        VAULT_ENC_KEY=$(openssl rand -hex 32)
        
        log "--> Generating Supabase JWT keys..."
        ANON_KEY=$(generate_jwt '{"role":"anon"}' "$JWT_SECRET")
        SERVICE_ROLE_KEY=$(generate_jwt '{"role":"service_role"}' "$JWT_SECRET")

        log "--> Saving configuration to '$CLIENT_CONFIG_FILE' for future use."
        cat > "$CLIENT_CONFIG_FILE" << EOL
# Client Server Configuration
N8N_DOMAIN_NAME=${N8N_DOMAIN_NAME}
SUBDOMAIN=${SUBDOMAIN}
NETWORK_NAME=${NETWORK_NAME}
SUPABASE_DOMAIN=${SUPABASE_DOMAIN}
VIBE_DOMAIN=${VIBE_DOMAIN}
FUNCTIONS_DOMAIN=${FUNCTIONS_DOMAIN}
SSL_EMAIL=${SSL_EMAIL}
SERVER_PUBLIC_IP=${SERVER_PUBLIC_IP}
LOGGING_SERVER_IP=${LOGGING_SERVER_IP}
GENERIC_TIMEZONE=${GENERIC_TIMEZONE}
N8N_DB_PASSWORD=${N8N_DB_PASSWORD}
SUPABASE_POSTGRES_PASSWORD=${SUPABASE_POSTGRES_PASSWORD}
JWT_SECRET=${JWT_SECRET}
ANON_KEY=${ANON_KEY}
SERVICE_ROLE_KEY=${SERVICE_ROLE_KEY}
DASHBOARD_USERNAME=${DASHBOARD_USERNAME}
DASHBOARD_PASSWORD=${DASHBOARD_PASSWORD}
SECRET_KEY_BASE=${SECRET_KEY_BASE}
VAULT_ENC_KEY=${VAULT_ENC_KEY}
OPENAI_API_KEY=${OPENAI_API_KEY}
GEMINI_API_KEY=${GEMINI_API_KEY}
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
N8N_PRE_PROCESS_WEBHOOK_URL=${N8N_PRE_PROCESS_WEBHOOK_URL}
N8N_POST_PROCESS_WEBHOOK_URL=${N8N_POST_PROCESS_WEBHOOK_URL}
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
    apt-get install -y postgresql postgresql-contrib net-tools
    
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
    for volume in caddy_data n8n_data; do
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
    local temp_dir="/tmp/docker-templates"
    log "--> Cloning template repository to $temp_dir..."
    rm -rf "$temp_dir"
    git clone "$TEMPLATE_REPO" "$temp_dir"
    
    log "--> Creating destination directories..."
    mkdir -p /home/n8n /home/supabase/docker /home/node-exporter /home/cadvisor /home/vibe-apps
    
    log "--> Copying and renaming template files..."
    cp "$temp_dir"/n8n_.env /home/n8n/.env
    cp "$temp_dir"/n8n_Dockerfile /home/n8n/Dockerfile
    cp "$temp_dir"/supabase_Dockerfile /home/supabase/docker/Dockerfile
    cp "$temp_dir"/n8n_docker-compose.yml /home/n8n/docker-compose.yml
    cp "$temp_dir"/Caddyfile /home/n8n/Caddyfile
    cp "$temp_dir"/supabase_.env /home/supabase/docker/.env
    cp "$temp_dir"/supabase_docker-compose.yml /home/supabase/docker/docker-compose.yml
    cp "$temp_dir"/node-exporter_docker-compose.yml /home/node-exporter/docker-compose.yml
    cp "$temp_dir"/cadvisor_docker-compose.yml /home/cadvisor/docker-compose.yml
    cp "$temp_dir"/vibe-apps_docker-compose.yml /home/vibe-apps/docker-compose.yml
    
    log "--> Creating Supabase database init script directories..."
    mkdir -p /home/supabase/docker/volumes/db/{_supabase.sql,jwt.sql,logs.sql,pooler.sql,realtime.sql,roles.sql,webhooks.sql}
    
    log "--> Creating Supabase Kong config directory and copying file..."
    mkdir -p /home/supabase/docker/volumes/api
    cp "$temp_dir"/supabase_kong.yml /home/supabase/docker/volumes/api/kong.yml

    log "--> Cloning Supabase edge functions repository..."
    mkdir -p /home/supabase/docker/volumes
    if [ -d "/home/supabase/docker/volumes/functions" ]; then
        log "--> Functions directory already exists. Skipping clone."
    else
        git clone "$SUPABASE_FUNCTIONS_REPO" /home/supabase/docker/volumes/functions
    fi

    log "--> Cloning vibe-apps repository..."
    if [ -d "/home/vibe-apps/vibe" ]; then
        log "--> Vibe-apps directory already exists. Skipping clone."
    else
        git clone "$VIBE_APPS_REPO" /home/vibe-apps/vibe
    fi

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
    sed -i "s|{{LOGGING_SERVER_IP}}|${LOGGING_SERVER_IP}|g" /home/n8n/Caddyfile

    # Process Supabase files
    sed -i "s|{{SUPABASE_POSTGRES_PASSWORD}}|${SUPABASE_POSTGRES_PASSWORD}|g" /home/supabase/docker/.env
    sed -i "s|{{JWT_SECRET}}|${JWT_SECRET}|g" /home/supabase/docker/.env
    sed -i "s|{{ANON_KEY}}|${ANON_KEY}|g" /home/supabase/docker/.env
    sed -i "s|{{SERVICE_ROLE_KEY}}|${SERVICE_ROLE_KEY}|g" /home/supabase/docker/.env
    sed -i "s|{{DASHBOARD_USERNAME}}|${DASHBOARD_USERNAME}|g" /home/supabase/docker/.env
    sed -i "s|{{DASHBOARD_PASSWORD}}|${DASHBOARD_PASSWORD}|g" /home/supabase/docker/.env
    sed -i "s|{{SECRET_KEY_BASE}}|${SECRET_KEY_BASE}|g" /home/supabase/docker/.env
    sed -i "s|{{VAULT_ENC_KEY}}|${VAULT_ENC_KEY}|g" /home/supabase/docker/.env
    sed -i "s|{{SUPABASE_SITE_URL}}|https://${SUPABASE_DOMAIN}|g" /home/supabase/docker/.env
    sed -i "s|{{NETWORK}}|${NETWORK_NAME}|g" /home/supabase/docker/docker-compose.yml
    sed -i "s|{{OPENAI_API_KEY}}|${OPENAI_API_KEY}|g" /home/supabase/docker/.env
    sed -i "s|{{GEMINI_API_KEY}}|${GEMINI_API_KEY}|g" /home/supabase/docker/.env
    sed -i "s|{{ANTHROPIC_API_KEY}}|${ANTHROPIC_API_KEY}|g" /home/supabase/docker/.env
    sed -i "s|{{N8N_PRE_PROCESS_WEBHOOK_URL}}|${N8N_PRE_PROCESS_WEBHOOK_URL}|g" /home/supabase/docker/.env
    sed -i "s|{{N8N_POST_PROCESS_WEBHOOK_URL}}|${N8N_POST_PROCESS_WEBHOOK_URL}|g" /home/supabase/docker/.env

    # Process monitoring files
    sed -i "s|{{NETWORK}}|${NETWORK_NAME}|g" /home/node-exporter/docker-compose.yml
    sed -i "s|{{NETWORK}}|${NETWORK_NAME}|g" /home/cadvisor/docker-compose.yml

    # Process vibe-apps files
    sed -i "s|{{NETWORK}}|${NETWORK_NAME}|g" /home/vibe-apps/docker-compose.yml

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
    log "--> Starting vibe-apps..."
    cd /home/vibe-apps && docker compose up -d
    log "--> Configuring firewall..."
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 5432/tcp
    ufw allow from "$LOGGING_SERVER_IP" to any port 9100 proto tcp
    ufw allow from "$LOGGING_SERVER_IP" to any port 8080 proto tcp
    ufw allow from "$LOGGING_SERVER_IP" to any port 9323 proto tcp
    ufw allow from "$LOGGING_SERVER_IP" to any port 9187 proto tcp
    ufw --force enable
    log "--> Restarting Docker to apply daemon configuration..."
    systemctl restart docker
    log "--> Restarting all services after Docker restart..."
    cd /home/n8n && docker compose up -d
    cd /home/supabase/docker && docker compose up -d
    cd /home/node-exporter && docker compose up -d
    cd /home/cadvisor && docker compose up -d
    cd /home/vibe-apps && docker compose up -d
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
    log "--------------------------------------------------"
    log ""
    log "Your services should be available shortly at:"
    log "n8n:                https://${SUBDOMAIN}.${N8N_DOMAIN_NAME}"
    log "n8n metrics:        https://${SUBDOMAIN}.${N8N_DOMAIN_NAME}/metrics (restricted to ${LOGGING_SERVER_IP})"
    log "Supabase:           https://${SUPABASE_DOMAIN}"
    log "Vibe Apps:          https://${VIBE_DOMAIN}"
    log "Edge Functions:     https://${FUNCTIONS_DOMAIN}"
    log ""
    log "Monitoring endpoints (accessible from ${LOGGING_SERVER_IP}):"
    log "node-exporter:      ${SERVER_PUBLIC_IP}:9100"
    log "cAdvisor:           ${SERVER_PUBLIC_IP}:8080"
    log "Docker metrics:     ${SERVER_PUBLIC_IP}:9323"
    log "Postgres exporter:  ${SERVER_PUBLIC_IP}:9187"
    log ""
    log "MANUAL NEXT STEPS:"
    log "1. Log in to the n8n UI and configure all necessary credentials."
    log "2. Install any required n8n community nodes."
    log "3. Configure your Prometheus server to scrape this client's metrics."
    log "4. If you skipped API keys, add them to /home/supabase/docker/.env and restart services."
    log "5. Verify all services are running correctly with 'docker ps -a'."
    log ""
    log "A full log of this session has been saved to: $LOG_FILE"
}

# Pipe all output of the main function to the log file and stdout
main 2>&1 | tee -a "$LOG_FILE"

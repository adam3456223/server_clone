#!/bin/bash

#
# Bit Creative - Client Server Setup Script
# Version: 1.3
# Author: Adam Fox & eVA
# Description: This script automates the setup of a new client server with
#              n8n, Supabase, and Caddy, using a standardized template repository.
#

# --- Configuration ---
set -e # Exit immediately if a command exits with a non-zero status.
readonly TEMPLATE_REPO="https://bit_creative@bitbucket.org/bit_creative/docker.git"
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
            "DASHBOARD_USERNAME" "DASHBOARD_PASSWORD" "SECRET_KEY_BASE" "VAULT_ENC_KEY"
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
        read -p "Enter the SSL contact email: " SSL_EMAIL
        read -p "Enter the desired username for the Supabase dashboard admin: " DASHBOARD_USERNAME; echo
        read -sp "Enter the desired password for the Supabase dashboard admin: " DASHBOARD_PASSWORD; echo
        read -p "Enter the desired Docker network name (e.g., bitcreative): " NETWORK_NAME

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
EOL
    fi
    log "--> Configuration loaded."
}

system_prep() {
    log "### Phase 3: Preparing System & Server ###"
    log "--> Applying kernel performance tuning..."
    cat <<EOL >> /etc/sysctl.conf
vm.swappiness=10
net.core.somaxconn=1024
EOL
    sysctl -p
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
    mkdir -p /home/n8n /home/supabase/docker
    log "--> Copying and renaming template files..."
    cp "$temp_dir"/n8n_.env /home/n8n/.env
    cp "$temp_dir"/n8n_Dockerfile /home/n8n/Dockerfile
    cp "$temp_dir"/supabase_Dockerfile /home/supabase/docker/Dockerfile
    cp "$temp_dir"/n8n_docker-compose.yml /home/n8n/docker-compose.yml
    cp "$temp_dir"/Caddyfile /home/n8n/Caddyfile
    cp "$temp_dir"/supabase_.env /home/supabase/docker/.env
    cp "$temp_dir"/supabase_docker-compose.yml /home/supabase/docker/docker-compose.yml
    # After copying other files, create the SQL init script directories
    log "--> Creating Supabase database init script directories..."
    mkdir -p /home/supabase/docker/volumes/db/{_supabase.sql,jwt.sql,logs.sql,pooler.sql,realtime.sql,roles.sql,webhooks.sql}
    log "--> Creating Supabase Kong config directory and copying file..."
    mkdir -p /home/supabase/docker/volumes/api
    cp "$temp_dir"/supabase_kong.yml /home/supabase/docker/volumes/api/kong.yml

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

    # Process Supabase files
    sed -i "s|{{SUPABASE_POSTGRES_PASSWORD}}|${SUPABASE_POSTGRES_PASSWORD}|g" /home/supabase/docker/.env
    sed -i "s|{{JWT_SECRET}}|${JWT_SECRET}|g" /home/supabase/docker/.env
    sed -i "s|{{ANON_KEY}}|${ANON_KEY}|g" /home/supabase/docker/.env
    sed -i "s|{{SERVICE_ROLE_KEY}}|${SERVICE_ROLE_KEY}|g" /home/supabase/docker/.env
    sed -i "s|{{DASHBOARD_USERNAME}}|${DASHBOARD_USERNAME}|g" /home/supabase/docker/.env
    sed -i "s|{{DASHBOARD_PASSWORD}}|${DASHBOARD_PASSWORD}|g" /home/supabase/docker/.env
    sed -i "s|{{SECRET_KEY_BASE}}|${SECRET_KEY_BASE}|g" /home/supabase/docker/.env
    sed -i "s|{{VAULT_ENC_KEY}}|${VAULT_ENC_KEY}|g" /home/supabase/docker/.env
    # Below also configures the PUBLILC_SITE_URL setting...
    sed -i "s|{{SUPABASE_SITE_URL}}|https://${SUPABASE_DOMAIN}|g" /home/supabase/docker/.env
    sed -i "s|{{NETWORK}}|${NETWORK_NAME}|g" /home/supabase/docker/docker-compose.yml

    log "--> Cleaning up temporary directory..."
    rm -rf "$temp_dir"
    log "--> File setup complete."
}

setup_host_postgres() {
    log "### Phase 6: Setting up Host PostgreSQL for n8n ###"
    log "--> Configuring PostgreSQL to listen on all interfaces..."
    sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" /etc/postgresql/14/main/postgresql.conf
    log "--> Allowing MD5 password authentication from Docker network..."
    echo "host    all             all             172.16.0.0/12           md5" >> /etc/postgresql/14/main/pg_hba.conf
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
    log "--> Configuring firewall..."
    ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp; ufw allow 5432/tcp
    ufw allow from "$LOGGING_SERVER_IP" to any port 9100 proto tcp
    ufw --force enable
    log "--> Restarting Docker to apply logging configuration..."
    systemctl restart docker
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
    log "n8n:      https://${SUBDOMAIN}.${N8N_DOMAIN_NAME}"
    log "Supabase: https://${SUPABASE_DOMAIN}"
    log ""
    log "MANUAL NEXT STEPS:"
    log "1. Log in to the n8n UI and configure all necessary credentials."
    log "2. Install any required n8n community nodes."
    log "3. Verify all services are running correctly with 'docker ps -a'."
    log ""
    log "A full log of this session has been saved to: $LOG_FILE"
}

# Pipe all output of the main function to the log file and stdout
main 2>&1 | tee -a "$LOG_FILE"

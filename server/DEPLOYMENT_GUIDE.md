# CyberCare Backend Deployment Guide

This guide provides step-by-step instructions for deploying the CyberCare backend system.

## Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu 20.04+ recommended), macOS, or Windows
- **Memory**: Minimum 2GB RAM, 4GB+ recommended
- **Storage**: 10GB+ available space
- **Network**: Internet connection for external API integrations

### Software Dependencies
- **Ballerina**: Version 2201.8.0 or later
- **MySQL**: Version 8.0 or later
- **Node.js**: Version 16+ (for frontend)
- **Git**: For version control

## Installation Steps

### 1. Install Ballerina

#### Ubuntu/Debian
```bash
# Download and install Ballerina
wget https://dist.ballerina.io/downloads/2201.8.0/ballerina-2201.8.0-swan-lake-linux-x64.deb
sudo dpkg -i ballerina-2201.8.0-swan-lake-linux-x64.deb

# Verify installation
bal version
```

#### macOS
```bash
# Using Homebrew
brew install ballerina

# Or download manually from https://ballerina.io/downloads/
```

#### Windows
```bash
# Download installer from https://ballerina.io/downloads/
# Run the installer and follow the setup wizard
```

### 2. Install MySQL

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install mysql-server
sudo mysql_secure_installation
```

#### macOS
```bash
brew install mysql
brew services start mysql
```

#### Windows
Download and install from [MySQL Downloads](https://dev.mysql.com/downloads/mysql/)

### 3. Clone the Repository

```bash
git clone https://github.com/your-org/cybercare-backend.git
cd cybercare-backend/server
```

### 4. Database Setup

#### Create Database and User
```sql
-- Connect to MySQL as root
mysql -u root -p

-- Create database
CREATE DATABASE cybercare_db;

-- Create application user
CREATE USER 'cybercare_app'@'localhost' IDENTIFIED BY 'secure_password_here';
GRANT SELECT, INSERT, UPDATE, DELETE ON cybercare_db.* TO 'cybercare_app'@'localhost';
FLUSH PRIVILEGES;

-- Exit MySQL
EXIT;
```

#### Run Database Schema
```bash
# From the server directory
mysql -u root -p cybercare_db < cybercare_schema.sql
```

### 5. Configuration Setup

#### Update config.toml
```toml
# Database Configuration
[cybercare.database]
host = "localhost"
username = "cybercare_app"
password = "secure_password_here"
database = "cybercare_db"
port = 3306

# JWT Configuration
[cybercare.jwt]
secret = "your-super-secret-jwt-key-change-in-production"
issuer = "cybercare-system"
audience = "cybercare-users"
expiration_time = 86400  # 24 hours

# Password Hashing
[cybercare.password]
secret = "your-password-hashing-secret"

# Email Configuration
[cybercare.email]
smtp_server = "smtp.gmail.com"
smtp_port = 587
username = "your-email@gmail.com"
password = "your-app-password"
from_address = "noreply@cybercare.com"

# External API Configuration
[cybercare.external_apis]
hibp_api_key = "your-hibp-api-key"
hibp_base_url = "https://haveibeenpwned.com/api/v3"
virustotal_api_key = "your-virustotal-api-key"
virustotal_base_url = "https://www.virustotal.com/api/v3"

# Server Configuration
[cybercare.server]
host = "localhost"
port = 8080
cors_allowed_origins = ["http://localhost:3000", "http://localhost:5173"]

# CERT Integration
[cybercare.cert]
email = "cert@your-government-agency.gov"
export_endpoint = "https://cert.gov/api/threats"
notification_enabled = true
```

### 6. API Keys Setup

#### HaveIBeenPwned API Key
1. Visit [HaveIBeenPwned API](https://haveibeenpwned.com/API/Key)
2. Purchase an API key
3. Add to `config.toml` under `hibp_api_key`

#### VirusTotal API Key
1. Create account at [VirusTotal](https://www.virustotal.com/)
2. Go to your profile and get API key
3. Add to `config.toml` under `virustotal_api_key`

#### Email Configuration
For Gmail:
1. Enable 2-factor authentication
2. Generate app password
3. Use app password in `config.toml`

### 7. Build and Run

#### Development Mode
```bash
# Install dependencies
bal deps pull

# Run the application
bal run

# The server will start on http://localhost:8080
```

#### Production Build
```bash
# Build executable
bal build

# Run the built jar
java -jar target/bin/cybercare_backend.jar
```

## Production Deployment

### 1. Environment Variables

Create a `.env` file or set environment variables:

```bash
# Database
export CYBERCARE_DB_HOST="your-db-host"
export CYBERCARE_DB_USERNAME="cybercare_app"
export CYBERCARE_DB_PASSWORD="secure-password"
export CYBERCARE_DB_DATABASE="cybercare_db"
export CYBERCARE_DB_PORT="3306"

# Security
export CYBERCARE_JWT_SECRET="your-production-jwt-secret"
export CYBERCARE_PASSWORD_SECRET="your-production-password-secret"

# External APIs
export CYBERCARE_HIBP_API_KEY="your-hibp-api-key"
export CYBERCARE_VT_API_KEY="your-virustotal-api-key"

# Email
export CYBERCARE_EMAIL_USERNAME="your-email@company.com"
export CYBERCARE_EMAIL_PASSWORD="your-email-password"

# Server
export CYBERCARE_SERVER_HOST="0.0.0.0"
export CYBERCARE_SERVER_PORT="8080"
```

### 2. Docker Deployment

#### Dockerfile
```dockerfile
FROM ballerina/ballerina:2201.8.0

WORKDIR /app

# Copy source code
COPY . .

# Build the application
RUN bal build

# Expose port
EXPOSE 8080

# Run the application
CMD ["bal", "run"]
```

#### Docker Compose
```yaml
version: '3.8'

services:
  cybercare-backend:
    build: .
    ports:
      - "8080:8080"
    environment:
      - CYBERCARE_DB_HOST=mysql
      - CYBERCARE_DB_USERNAME=cybercare_app
      - CYBERCARE_DB_PASSWORD=secure_password
      - CYBERCARE_DB_DATABASE=cybercare_db
    depends_on:
      - mysql
    networks:
      - cybercare-network

  mysql:
    image: mysql:8.0
    environment:
      - MYSQL_ROOT_PASSWORD=root_password
      - MYSQL_DATABASE=cybercare_db
      - MYSQL_USER=cybercare_app
      - MYSQL_PASSWORD=secure_password
    volumes:
      - mysql_data:/var/lib/mysql
      - ./cybercare_schema.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - cybercare-network

volumes:
  mysql_data:

networks:
  cybercare-network:
    driver: bridge
```

#### Build and Deploy
```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f cybercare-backend

# Stop services
docker-compose down
```

### 3. Kubernetes Deployment

#### Database ConfigMap
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cybercare-config
data:
  config.toml: |
    [cybercare.database]
    host = "mysql-service"
    username = "cybercare_app"
    password = "secure_password"
    database = "cybercare_db"
    port = 3306
    # ... other configuration
```

#### Application Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cybercare-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cybercare-backend
  template:
    metadata:
      labels:
        app: cybercare-backend
    spec:
      containers:
      - name: cybercare-backend
        image: cybercare/backend:latest
        ports:
        - containerPort: 8080
        env:
        - name: CYBERCARE_DB_HOST
          value: "mysql-service"
        volumeMounts:
        - name: config-volume
          mountPath: /app/config.toml
          subPath: config.toml
      volumes:
      - name: config-volume
        configMap:
          name: cybercare-config
```

#### Service
```yaml
apiVersion: v1
kind: Service
metadata:
  name: cybercare-backend-service
spec:
  selector:
    app: cybercare-backend
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: LoadBalancer
```

### 4. Reverse Proxy (Nginx)

#### Nginx Configuration
```nginx
server {
    listen 80;
    server_name api.cybercare.com;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# HTTPS Configuration (with SSL certificate)
server {
    listen 443 ssl;
    server_name api.cybercare.com;

    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Monitoring and Logging

### 1. Health Checks

Set up automated health checks:

```bash
#!/bin/bash
# health-check.sh

HEALTH_URL="http://localhost:8080/api/health/system"
RESPONSE=$(curl -s $HEALTH_URL)

if echo "$RESPONSE" | grep -q '"status":"healthy"'; then
    echo "✅ CyberCare backend is healthy"
    exit 0
else
    echo "❌ CyberCare backend is unhealthy"
    echo "Response: $RESPONSE"
    exit 1
fi
```

### 2. Log Management

#### Ballerina Logging Configuration
```toml
[ballerina.log]
level = "INFO"
console = true
format = "%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n"

# File logging
[[ballerina.log.appenders]]
name = "FILE"
class = "ch.qos.logback.core.rolling.RollingFileAppender"
file = "logs/cybercare.log"
```

### 3. Performance Monitoring

#### Metrics Collection
```bash
# Install Prometheus and Grafana for monitoring
# Ballerina provides built-in metrics

# Enable observability in config
[ballerina.observe]
enabled = true
provider = "prometheus"
```

## Security Considerations

### 1. Network Security
```bash
# Firewall configuration (UFW on Ubuntu)
sudo ufw allow 22    # SSH
sudo ufw allow 80    # HTTP
sudo ufw allow 443   # HTTPS
sudo ufw allow 8080  # Application (if direct access needed)
sudo ufw enable
```

### 2. Database Security
```sql
-- Remove default accounts
DROP USER IF EXISTS ''@'localhost';
DROP USER IF EXISTS ''@'%';

-- Set strong passwords
ALTER USER 'root'@'localhost' IDENTIFIED BY 'very-strong-root-password';

-- Limit connections
SET GLOBAL max_connections = 100;
```

### 3. Application Security
```toml
# Use strong secrets in production
[cybercare.jwt]
secret = "use-a-very-long-random-string-here-at-least-64-characters-long"

[cybercare.password]
secret = "another-very-long-random-string-for-password-hashing"
```

## Backup and Recovery

### 1. Database Backup
```bash
#!/bin/bash
# backup.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/cybercare"
mkdir -p $BACKUP_DIR

# Create database backup
mysqldump -u root -p cybercare_db > "$BACKUP_DIR/cybercare_db_$DATE.sql"

# Compress backup
gzip "$BACKUP_DIR/cybercare_db_$DATE.sql"

# Remove backups older than 30 days
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete

echo "Backup completed: cybercare_db_$DATE.sql.gz"
```

### 2. Automated Backup (Cron)
```bash
# Add to crontab (crontab -e)
0 2 * * * /path/to/backup.sh
```

### 3. Recovery
```bash
# Restore from backup
gunzip cybercare_db_20241215_020000.sql.gz
mysql -u root -p cybercare_db < cybercare_db_20241215_020000.sql
```

## Troubleshooting

### Common Issues

#### 1. Database Connection Failed
```bash
# Check MySQL status
sudo systemctl status mysql

# Check MySQL error logs
sudo tail -f /var/log/mysql/error.log

# Test connection
mysql -u cybercare_app -p -h localhost cybercare_db
```

#### 2. API Key Issues
```bash
# Test HaveIBeenPwned API
curl -H "hibp-api-key: your-api-key" \
     "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com"

# Test VirusTotal API
curl -H "x-apikey: your-api-key" \
     "https://www.virustotal.com/api/v3/urls/limits"
```

#### 3. Email Issues
```bash
# Test SMTP connection
telnet smtp.gmail.com 587

# Check email logs in application logs
tail -f logs/cybercare.log | grep -i email
```

#### 4. Performance Issues
```bash
# Check system resources
htop
df -h
free -m

# Check MySQL performance
mysql -u root -p -e "SHOW PROCESSLIST;"
mysql -u root -p -e "SHOW ENGINE INNODB STATUS\G"
```

## Scaling and Load Balancing

### 1. Horizontal Scaling
```bash
# Run multiple instances
bal run --port 8080 &
bal run --port 8081 &
bal run --port 8082 &
```

### 2. Load Balancer Configuration (HAProxy)
```
backend cybercare_backend
    balance roundrobin
    server app1 localhost:8080 check
    server app2 localhost:8081 check
    server app3 localhost:8082 check
```

### 3. Database Scaling
```sql
-- Read replicas for scaling reads
-- Master-slave configuration
-- Connection pooling optimization
```

## Maintenance

### 1. Regular Updates
```bash
# Update system packages
sudo apt update && sudo apt upgrade

# Update Ballerina
# Check for new versions and update accordingly
```

### 2. Database Maintenance
```sql
-- Optimize tables
OPTIMIZE TABLE threat_reports;
OPTIMIZE TABLE users;
OPTIMIZE TABLE breach_scan_logs;

-- Update statistics
ANALYZE TABLE threat_reports;
```

### 3. Log Rotation
```bash
# Configure logrotate
sudo nano /etc/logrotate.d/cybercare

# Add configuration:
/var/log/cybercare/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    copytruncate
}
```

## Support and Maintenance

- **Health Check Endpoint**: `GET /api/health/system`
- **Logs Location**: `/var/log/cybercare/` or `logs/` directory
- **Configuration**: `config.toml`
- **Database**: MySQL on port 3306
- **Application**: Ballerina on port 8080

For issues and support, check:
1. Application logs
2. Database logs
3. System resource usage
4. External API status
5. Network connectivity

This deployment guide should help you successfully deploy and maintain the CyberCare backend system in production.
# CyberCare Database Configuration Guide

This guide provides step-by-step instructions for setting up the database configuration for the CyberCare project.

## Prerequisites

- **MySQL Server 8.0+** installed and running
- **Ballerina 2201.8.0+** installed
- **MySQL Workbench** or any MySQL client (optional but recommended)

## Step 1: Install MySQL and Create Database

### Install MySQL (if not already installed)

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install mysql-server
sudo mysql_secure_installation
```

**macOS (using Homebrew):**
```bash
brew install mysql
brew services start mysql
```

**Windows:**
Download and install from [MySQL Downloads](https://dev.mysql.com/downloads/mysql/)

### Create Database
1. Connect to MySQL as root:
   ```bash
   mysql -u root -p
   ```

2. Run the schema file:
   ```bash
   mysql -u root -p < cybercare_schema.sql
   ```

   Or manually create the database:
   ```sql
   CREATE DATABASE cybercare_db;
   USE cybercare_db;
   ```

## Step 2: Configure Database Connection

### Update config.toml

Edit the `config.toml` file in your server directory:

```toml
[cybercare.database]
host = "localhost"          # Your MySQL server host
username = "root"           # Your MySQL username
password = "your_password"  # Your MySQL password
database = "cybercare_db"   # Database name
port = 3306                # MySQL port (default: 3306)
```

**Important:** 
- Replace `"your_password"` with your actual MySQL root password
- If using a different user, update the username accordingly
- Ensure the database name matches what you created

## Step 3: Run Database Schema

Execute the SQL schema file to create all required tables:

```bash
# From the server directory
mysql -u root -p cybercare_db < cybercare_schema.sql
```

Or copy and paste the contents of `cybercare_schema.sql` into your MySQL client.

## Step 4: Verify Database Setup

### Check Tables Created
```sql
USE cybercare_db;
SHOW TABLES;
```

You should see these tables:
- `users`
- `admins`
- `breach_scan_logs`
- `threat_reports`
- `virustotal_scans`
- `notifications`
- `cert_exports`
- `api_logs`
- `system_settings`

### Test Connection
Run the Ballerina service to test the connection:

```bash
# From the server directory
bal run
```

Check the health endpoint:
```bash
curl http://localhost:8080/api/health/database
```

## Step 5: Database Schema Overview

### Core Tables

#### users
Stores user account information with email verification support.

#### threat_reports
Central table for threat submissions with status tracking.

#### breach_scan_logs
Logs of HaveIBeenPwned API scans for user emails.

#### virustotal_scans
Results from VirusTotal API scans for threat validation.

#### notifications
In-app and email notification management.

#### cert_exports
Tracks threat reports exported to CERT agencies.

### Key Features

1. **UUID Primary Keys**: All tables use UUID strings for better security
2. **JSON Support**: Flexible data storage for API responses and metadata
3. **Timestamp Tracking**: Created/updated timestamps for audit trails
4. **Foreign Key Constraints**: Data integrity enforcement
5. **Indexes**: Optimized query performance
6. **Enums**: Type safety for status fields

## Step 6: Production Configuration

### Security Considerations

1. **Change Default Passwords**: Update all default passwords in production
2. **Create Dedicated User**: Don't use root for application connections
3. **SSL/TLS**: Enable encrypted connections
4. **Firewall**: Restrict database access to application servers only

### Create Application User
```sql
-- Create dedicated user for the application
CREATE USER 'cybercare_app'@'localhost' IDENTIFIED BY 'secure_password_here';

-- Grant necessary permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON cybercare_db.* TO 'cybercare_app'@'localhost';

-- Apply changes
FLUSH PRIVILEGES;
```

Update config.toml:
```toml
[cybercare.database]
host = "localhost"
username = "cybercare_app"
password = "secure_password_here"
database = "cybercare_db"
port = 3306
```

### Environment Variables (Recommended for Production)

Instead of hardcoding in config.toml, use environment variables:

```bash
export CYBERCARE_DB_HOST="localhost"
export CYBERCARE_DB_USERNAME="cybercare_app"
export CYBERCARE_DB_PASSWORD="secure_password"
export CYBERCARE_DB_DATABASE="cybercare_db"
export CYBERCARE_DB_PORT="3306"
```

## Step 7: Troubleshooting

### Common Issues

#### Connection Refused
- Ensure MySQL server is running: `sudo systemctl status mysql`
- Check if port 3306 is open: `netstat -tulpn | grep 3306`
- Verify firewall settings

#### Access Denied
- Check username/password in config.toml
- Verify user permissions: `SHOW GRANTS FOR 'username'@'localhost';`
- Ensure user can connect from the application host

#### Database Not Found
- Verify database exists: `SHOW DATABASES;`
- Check database name spelling in config.toml
- Ensure schema was applied successfully

#### Table Not Found
- Run the schema file: `mysql -u root -p cybercare_db < cybercare_schema.sql`
- Check if all tables were created: `SHOW TABLES;`

### Testing Database Connection

Create a simple test script:

```ballerina
// test_db.bal
import cybercare_backend.db;
import ballerina/log;

public function main() returns error? {
    log:printInfo("Testing database connection...");
    
    boolean|error result = db:testConnection();
    if result is boolean && result {
        log:printInfo("✅ Database connection successful!");
    } else {
        log:printError("❌ Database connection failed!");
        return result is error ? result : error("Connection test failed");
    }
    
    boolean|error schemaResult = db:validateSchema();
    if schemaResult is boolean && schemaResult {
        log:printInfo("✅ Database schema validation successful!");
    } else {
        log:printWarn("⚠️ Database schema validation failed or incomplete!");
    }
    
    error? closeResult = db:closeConnection();
    if closeResult is error {
        log:printError("Error closing connection: " + closeResult.message());
    }
}
```

Run the test:
```bash
bal run test_db.bal
```

## Step 8: Backup and Maintenance

### Regular Backups
```bash
# Create backup
mysqldump -u root -p cybercare_db > cybercare_backup_$(date +%Y%m%d).sql

# Restore backup
mysql -u root -p cybercare_db < cybercare_backup_20241215.sql
```

### Performance Monitoring
- Monitor connection pool usage
- Check slow query logs
- Review table sizes and optimize indexes

### Updates and Migrations
- Always backup before schema changes
- Test migrations on development environment first
- Use version control for schema changes

## Next Steps

After completing the database setup:

1. **Configure External APIs**: Set up HaveIBeenPwned and VirusTotal API keys
2. **Email Configuration**: Configure SMTP settings for notifications
3. **JWT Configuration**: Set up authentication secrets
4. **Start Development**: Begin implementing API endpoints

For questions or issues, refer to the Ballerina MySQL connector documentation or create an issue in the project repository.
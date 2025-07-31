import ballerinax/mysql;
import ballerinax/mysql.driver as _;
import ballerina/log;
import ballerina/sql;

// Database configuration variables - these will be read from config.toml
configurable string host = ?;
configurable string username = ?;
configurable string password = ?;
configurable string database = ?;
configurable int port = ?;

// Database connection pool configuration for better performance
mysql:ConnectionPool connectionPool = {
    maxOpenConnections: 20,
    maxConnectionLifeTime: 900, // 15 minutes
    minIdleConnections: 5
};

// Database connection options
mysql:Options connectionOptions = {
    connectionPool: connectionPool,
    useSSL: false,
    allowPublicKeyRetrieval: true
};

// Initialize MySQL client with connection pooling - this creates a singleton connection
final mysql:Client dbClient = check new (
    host = host,
    user = username,
    password = password,
    database = database,
    port = port,
    options = connectionOptions
);

// Public function to get the database connection
public function getConnection() returns mysql:Client {
    return dbClient;
}

// Function to test database connectivity
public function testConnection() returns boolean|error {
    log:printInfo("Testing database connection...");
    
    sql:ParameterizedQuery query = `SELECT 1 as test`;
    stream<record {}, error?> resultStream = dbClient->query(query);
    
    record {|record {} value;|}? result = check resultStream.next();
    check resultStream.close();
    
    if result is record {|record {} value;|} {
        log:printInfo("Database connection successful");
        return true;
    } else {
        log:printError("Database connection failed");
        return false;
    }
}

// Function to validate database schema exists
public function validateSchema() returns boolean|error {
    log:printInfo("Validating database schema...");
    
    sql:ParameterizedQuery query = `SELECT COUNT(*) as table_count FROM information_schema.tables 
                                   WHERE table_schema = ${database}`;
    
    stream<record {}, error?> resultStream = dbClient->query(query);
    record {|record {} value;|}? result = check resultStream.next();
    check resultStream.close();
    
    if result is record {|record {} value;|} {
        record {} tableCountRecord = result.value;
        if tableCountRecord.hasKey("table_count") {
            int tableCount = <int>tableCountRecord["table_count"];
            if tableCount >= 8 { // We expect at least 8 tables for CyberCare
                log:printInfo(string `Database schema validation successful. Found ${tableCount} tables.`);
                return true;
            } else {
                log:printWarn(string `Database schema incomplete. Expected at least 8 tables, found ${tableCount}.`);
                return false;
            }
        }
    }
    
    log:printError("Database schema validation failed");
    return false;
}

// Function to close database connection gracefully
public function closeConnection() returns error? {
    log:printInfo("Closing database connection...");
    check dbClient.close();
    log:printInfo("Database connection closed successfully");
}
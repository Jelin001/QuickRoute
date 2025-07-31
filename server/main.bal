import ballerina/http;
import ballerina/log;
import ballerina/time;
import ballerina/runtime;
import cybercare_backend.db;

// Server configuration
configurable string host = ?;
configurable int port = ?;
configurable string[] cors_allowed_origins = ?;

// HTTP service configuration
http:Service cybercareService = service object {
    
    // Health check endpoint
    resource function get health() returns json {
        return {
            "status": "healthy",
            "service": "CyberCare Backend",
            "timestamp": time:utcNow()
        };
    }
    
    // Database health check
    resource function get health/database() returns json|error {
        boolean|error dbStatus = db:testConnection();
        
        if dbStatus is boolean && dbStatus {
            return {
                "status": "healthy",
                "database": "connected",
                "timestamp": time:utcNow()
            };
        } else {
            return {
                "status": "error",
                "database": "disconnected",
                "error": dbStatus is error ? dbStatus.message() : "Unknown error",
                "timestamp": time:utcNow()
            };
        }
    }
};

// CORS configuration
http:CorsConfig corsConfig = {
    allowOrigins: cors_allowed_origins,
    allowCredentials: true,
    allowHeaders: ["Authorization", "Content-Type", "X-Requested-With"],
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    maxAge: 84900
};

// HTTP listener configuration
listener http:Listener httpListener = new (port, {
    host: host,
    corsConfig: corsConfig
});

// Main service initialization
public function main() returns error? {
    log:printInfo("Starting CyberCare Backend Server...");
    
    // Test database connection on startup
    boolean|error dbConnection = db:testConnection();
    if dbConnection is error {
        log:printError("Failed to connect to database: " + dbConnection.message());
        return dbConnection;
    }
    
    // Validate database schema
    boolean|error schemaValid = db:validateSchema();
    if schemaValid is error {
        log:printError("Database schema validation failed: " + schemaValid.message());
        return schemaValid;
    }
    
    if schemaValid == false {
        log:printWarn("Database schema is incomplete. Please run the schema script.");
    }
    
    // Attach service to listener
    check httpListener.attach(cybercareService, "/api");
    
    // Start the listener
    check httpListener.'start();
    
    log:printInfo("CyberCare Backend Server started successfully");
    log:printInfo(string `Server running on http://${host}:${port}`);
    log:printInfo("API endpoints available at http://${host}:${port}/api");
    
    // Keep the service running
    runtime:registerListener(httpListener);
}

// Graceful shutdown
public function shutdown() {
    log:printInfo("Shutting down CyberCare Backend Server...");
    
    // Close database connections
    error? dbCloseResult = db:closeConnection();
    if dbCloseResult is error {
        log:printError("Error closing database connection: " + dbCloseResult.message());
    }
    
    log:printInfo("Server shutdown complete");
}
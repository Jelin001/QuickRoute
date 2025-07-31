import ballerina/http;
import ballerina/log;
import ballerina/time;
import ballerina/runtime;
import cybercare_backend.db;
import cybercare_backend.hibp;
import cybercare_backend.virustotal as vt;
import cybercare_backend.email;

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
            "version": "1.0.0",
            "timestamp": time:utcNow()
        };
    }
    
    // Comprehensive system health check
    resource function get health/system() returns json|error {
        boolean|error dbStatus = db:testConnection();
        boolean hibpStatus = hibp:testHIBPConnection();
        boolean vtStatus = vt:testVirusTotalConnection();
        boolean emailStatus = email:testEmailConnection();
        
        json healthData = {
            "status": "healthy",
            "services": {
                "database": {
                    "status": dbStatus is boolean && dbStatus ? "healthy" : "error",
                    "error": dbStatus is error ? dbStatus.message() : ()
                },
                "hibp": {
                    "status": hibpStatus ? "healthy" : "error"
                },
                "virustotal": {
                    "status": vtStatus ? "healthy" : "error"
                },
                "email": {
                    "status": emailStatus ? "healthy" : "error"
                }
            },
            "timestamp": time:utcNow()
        };
        
        // Determine overall status
        boolean allHealthy = (dbStatus is boolean && dbStatus) && hibpStatus && vtStatus && emailStatus;
        if !allHealthy {
            healthData = {
                ...healthData,
                "status": "degraded"
            };
        }
        
        return healthData;
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
    
    // API documentation endpoint
    resource function get docs() returns json {
        return {
            "service": "CyberCare API",
            "version": "1.0.0",
            "description": "Community-Powered Cyber Threat Monitoring System",
            "endpoints": {
                "auth": {
                    "POST /api/users/signup": "User registration",
                    "POST /api/users/login": "User login",
                    "GET /api/users/me": "Get user profile",
                    "POST /api/users/verify-email": "Verify email address",
                    "POST /api/users/rescan-breaches": "Rescan email for breaches"
                },
                "threats": {
                    "POST /api/threats/reports": "Submit threat report",
                    "GET /api/threats/reports": "Get user's threat reports",
                    "GET /api/threats/reports/{id}": "Get specific threat report",
                    "GET /api/threats/stats": "Get threat statistics",
                    "GET /api/threats/admin/reports": "Get all reports (admin)",
                    "PUT /api/threats/reports/{id}/status": "Update report status (admin)"
                },
                "system": {
                    "GET /api/health": "Basic health check",
                    "GET /api/health/system": "Comprehensive system health",
                    "GET /api/health/database": "Database health check",
                    "GET /api/docs": "API documentation"
                }
            },
            "authentication": {
                "type": "Bearer Token (JWT)",
                "header": "Authorization: Bearer <token>"
            },
            "timestamp": time:utcNow()
        };
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
import ballerina/jwt;
import ballerina/time;
import ballerina/log;
import ballerina/uuid;

// JWT configuration
configurable string secret = ?;
configurable string issuer = ?;
configurable string audience = ?;
configurable int expiration_time = ?;

// JWT issuer configuration
jwt:IssuerConfig jwtIssuerConfig = {
    username: "cybercare-system",
    issuer: issuer,
    audience: audience,
    keyId: "cybercare-key",
    jwtId: "",
    customClaims: {},
    expTime: expiration_time,
    signatureConfig: {
        config: {
            keyStore: {
                path: "",
                password: ""
            },
            keyAlias: "",
            keyPassword: ""
        }
    }
};

// JWT validator configuration  
jwt:ValidatorConfig jwtValidatorConfig = {
    issuer: issuer,
    audience: audience,
    signatureConfig: {
        secret: secret
    },
    cacheConfig: {
        capacity: 100,
        evictionFactor: 0.25
    }
};

// Generate JWT token for user
public function generateToken(string userId, string email, string name, string? role = ()) returns string|error {
    time:Utc currentTime = time:utcNow();
    int currentTimestamp = <int>time:utcToEpochSeconds(currentTime);
    
    jwt:IssuerConfig config = {
        username: userId,
        issuer: issuer,
        audience: audience,
        keyId: "cybercare-key",
        jwtId: uuid:createType1AsString(),
        customClaims: {
            "sub": userId,
            "email": email,
            "name": name,
            "role": role ?: ()
        },
        expTime: currentTimestamp + expiration_time,
        signatureConfig: {
            config: {
                secret: secret
            }
        }
    };
    
    string|jwt:Error jwtToken = jwt:issue(config);
    if jwtToken is jwt:Error {
        log:printError("Error generating JWT token: " + jwtToken.message());
        return error("Failed to generate authentication token");
    }
    
    return jwtToken;
}

// Validate JWT token
public function validateToken(string token) returns jwt:Payload|error {
    jwt:Payload|jwt:Error payload = jwt:validate(token, jwtValidatorConfig);
    
    if payload is jwt:Error {
        log:printError("JWT validation failed: " + payload.message());
        return error("Invalid or expired token");
    }
    
    return payload;
}

// Extract user ID from token
public function getUserIdFromToken(string token) returns string|error {
    jwt:Payload payload = check validateToken(token);
    
    if payload.customClaims.hasKey("sub") {
        return payload.customClaims["sub"].toString();
    }
    
    return error("User ID not found in token");
}

// Extract user email from token
public function getEmailFromToken(string token) returns string|error {
    jwt:Payload payload = check validateToken(token);
    
    if payload.customClaims.hasKey("email") {
        return payload.customClaims["email"].toString();
    }
    
    return error("Email not found in token");
}

// Extract user role from token
public function getRoleFromToken(string token) returns string|error {
    jwt:Payload payload = check validateToken(token);
    
    if payload.customClaims.hasKey("role") && payload.customClaims["role"] != () {
        return payload.customClaims["role"].toString();
    }
    
    return error("Role not found in token");
}

// Check if token is expired
public function isTokenExpired(string token) returns boolean {
    jwt:Payload|error payload = validateToken(token);
    
    if payload is error {
        return true; // Consider invalid tokens as expired
    }
    
    time:Utc currentTime = time:utcNow();
    int currentTimestamp = <int>time:utcToEpochSeconds(currentTime);
    
    return payload.exp < currentTimestamp;
}

// Refresh token (generate new token with same claims but extended expiry)
public function refreshToken(string oldToken) returns string|error {
    jwt:Payload payload = check validateToken(oldToken);
    
    // Extract user details from old token
    string userId = payload.customClaims["sub"].toString();
    string email = payload.customClaims["email"].toString();
    string name = payload.customClaims["name"].toString();
    string? role = payload.customClaims.hasKey("role") && payload.customClaims["role"] != () ? 
                   payload.customClaims["role"].toString() : ();
    
    // Generate new token with extended expiry
    return generateToken(userId, email, name, role);
}
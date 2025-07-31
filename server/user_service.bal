import ballerina/http;
import ballerina/log;
import ballerina/sql;
import ballerina/time;
import ballerina/uuid;
import cybercare_backend.db;
import cybercare_backend.password;
import cybercare_backend.jwt;
import cybercare_backend.email;
import cybercare_backend.hibp;

// User service
service /users on new http:Listener(8080) {

    // User signup
    resource function post signup(UserRegistration userReg) returns http:Created|http:BadRequest|http:Conflict|http:InternalServerError {
        log:printInfo(string `User signup attempt: ${userReg.email}`);
        
        // Validate input
        if userReg.email.trim() == "" || userReg.password.trim() == "" || userReg.name.trim() == "" {
            return http:BAD_REQUEST;
        }
        
        // Validate email format
        if !isValidEmail(userReg.email) {
            return <http:BadRequest>{ body: { success: false, message: "Invalid email format" } };
        }
        
        // Validate password strength
        if !password:validatePasswordStrength(userReg.password) {
            return <http:BadRequest>{ 
                body: { 
                    success: false, 
                    message: "Password must be at least 8 characters with uppercase, lowercase, and digit" 
                } 
            };
        }
        
        // Check if user already exists
        boolean|error userExists = checkUserExists(userReg.email);
        if userExists is error {
            log:printError("Error checking user existence: " + userExists.message());
            return <http:InternalServerError>{ body: { success: false, message: "Internal server error" } };
        }
        
        if userExists {
            return <http:Conflict>{ body: { success: false, message: "User already exists with this email" } };
        }
        
        // Hash password
        string|error hashedPassword = password:hashPassword(userReg.password);
        if hashedPassword is error {
            log:printError("Error hashing password: " + hashedPassword.message());
            return <http:InternalServerError>{ body: { success: false, message: "Failed to process password" } };
        }
        
        // Generate verification token
        string|error verificationToken = password:generateVerificationToken();
        if verificationToken is error {
            log:printError("Error generating verification token: " + verificationToken.message());
            return <http:InternalServerError>{ body: { success: false, message: "Failed to generate verification token" } };
        }
        
        // Create user
        string userId = uuid:createType1AsString();
        time:Utc currentTime = time:utcNow();
        
        User newUser = {
            id: userId,
            email: userReg.email.toLowerAscii(),
            password_hash: hashedPassword,
            name: userReg.name,
            email_verified: false,
            verification_token: verificationToken,
            created_at: currentTime,
            updated_at: currentTime,
            is_active: true
        };
        
        // Store user in database
        error? createResult = createUser(newUser);
        if createResult is error {
            log:printError("Error creating user: " + createResult.message());
            return <http:InternalServerError>{ body: { success: false, message: "Failed to create user account" } };
        }
        
        // Send verification email
        error? emailResult = email:sendEmailVerification(userReg.email, userReg.name, verificationToken);
        if emailResult is error {
            log:printWarn("Failed to send verification email: " + emailResult.message());
            // Continue even if email fails
        }
        
        // Scan email for breaches (async)
        worker breachScanWorker {
            BreachScanLog|error scanResult = hibp:checkEmailBreach(userReg.email, userId, "signup");
            if scanResult is error {
                log:printError("Failed to scan email for breaches: " + scanResult.message());
            } else if scanResult.scan_result == "breached" {
                log:printInfo(string `New user ${userReg.email} has been found in breaches`);
                // Could trigger notification here
            }
        }
        
        return <http:Created>{ 
            body: { 
                success: true, 
                message: "Account created successfully. Please check your email for verification.",
                data: {
                    "userId": userId,
                    "email": userReg.email,
                    "emailVerified": false
                }
            } 
        };
    }

    // User login
    resource function post login(UserLogin loginData) returns http:Ok|http:BadRequest|http:Unauthorized|http:InternalServerError {
        log:printInfo(string `User login attempt: ${loginData.email}`);
        
        // Validate input
        if loginData.email.trim() == "" || loginData.password.trim() == "" {
            return http:BAD_REQUEST;
        }
        
        // Get user from database
        User|error? user = getUserByEmail(loginData.email);
        if user is error {
            log:printError("Error fetching user: " + user.message());
            return <http:InternalServerError>{ body: { success: false, message: "Internal server error" } };
        }
        
        if user is () {
            return <http:Unauthorized>{ body: { success: false, message: "Invalid email or password" } };
        }
        
        // Check if account is active
        if !user.is_active {
            return <http:Unauthorized>{ body: { success: false, message: "Account is deactivated" } };
        }
        
        // Verify password
        boolean|error passwordValid = password:verifyPassword(loginData.password, user.password_hash);
        if passwordValid is error {
            log:printError("Error verifying password: " + passwordValid.message());
            return <http:InternalServerError>{ body: { success: false, message: "Authentication error" } };
        }
        
        if !passwordValid {
            return <http:Unauthorized>{ body: { success: false, message: "Invalid email or password" } };
        }
        
        // Check for admin role
        string? adminRole = getAdminRole(user.id);
        
        // Generate JWT token
        string|error token = jwt:generateToken(user.id, user.email, user.name, adminRole);
        if token is error {
            log:printError("Error generating token: " + token.message());
            return <http:InternalServerError>{ body: { success: false, message: "Failed to generate authentication token" } };
        }
        
        // Update last login
        error? updateResult = updateLastLogin(user.id);
        if updateResult is error {
            log:printWarn("Failed to update last login: " + updateResult.message());
        }
        
        // Create user profile
        UserProfile userProfile = {
            id: user.id,
            email: user.email,
            name: user.name,
            email_verified: user.email_verified,
            created_at: user.created_at,
            last_login: time:utcNow()
        };
        
        AuthResponse authResponse = {
            token: token,
            user: userProfile,
            message: "Login successful"
        };
        
        return <http:Ok>{ 
            body: { 
                success: true, 
                message: "Login successful",
                data: authResponse
            } 
        };
    }

    // Get user profile
    resource function get me(@http:Header {name: "Authorization"} string? authHeader) returns http:Ok|http:Unauthorized|http:InternalServerError {
        if authHeader is () || !authHeader.startsWith("Bearer ") {
            return <http:Unauthorized>{ body: { success: false, message: "Authorization header required" } };
        }
        
        string token = authHeader.substring(7); // Remove "Bearer " prefix
        
        // Validate token and get user ID
        string|error userId = jwt:getUserIdFromToken(token);
        if userId is error {
            return <http:Unauthorized>{ body: { success: false, message: "Invalid or expired token" } };
        }
        
        // Get user from database
        User|error? user = getUserById(userId);
        if user is error {
            log:printError("Error fetching user: " + user.message());
            return <http:InternalServerError>{ body: { success: false, message: "Internal server error" } };
        }
        
        if user is () {
            return <http:Unauthorized>{ body: { success: false, message: "User not found" } };
        }
        
        // Get breach history
        BreachScanLog[]|error breachHistory = hibp:getUserBreachHistory(userId);
        if breachHistory is error {
            log:printWarn("Failed to get breach history: " + breachHistory.message());
            breachHistory = [];
        }
        
        UserProfile userProfile = {
            id: user.id,
            email: user.email,
            name: user.name,
            email_verified: user.email_verified,
            created_at: user.created_at,
            last_login: user.last_login,
            breachHistory: breachHistory
        };
        
        return <http:Ok>{ 
            body: { 
                success: true,
                data: userProfile
            } 
        };
    }

    // Verify email
    resource function post verify\-email(http:Request req) returns http:Ok|http:BadRequest|http:NotFound|http:InternalServerError {
        json|error payload = req.getJsonPayload();
        if payload is error {
            return <http:BadRequest>{ body: { success: false, message: "Invalid request body" } };
        }
        
        if !(payload is map<json>) || !payload.hasKey("token") {
            return <http:BadRequest>{ body: { success: false, message: "Verification token required" } };
        }
        
        string verificationToken = payload["token"].toString();
        
        // Find user by verification token
        User|error? user = getUserByVerificationToken(verificationToken);
        if user is error {
            log:printError("Error fetching user by token: " + user.message());
            return <http:InternalServerError>{ body: { success: false, message: "Internal server error" } };
        }
        
        if user is () {
            return <http:NotFound>{ body: { success: false, message: "Invalid or expired verification token" } };
        }
        
        // Verify email
        error? verifyResult = verifyUserEmail(user.id);
        if verifyResult is error {
            log:printError("Error verifying email: " + verifyResult.message());
            return <http:InternalServerError>{ body: { success: false, message: "Failed to verify email" } };
        }
        
        // Send welcome email
        error? welcomeResult = email:sendWelcomeEmail(user.email, user.name);
        if welcomeResult is error {
            log:printWarn("Failed to send welcome email: " + welcomeResult.message());
        }
        
        return <http:Ok>{ 
            body: { 
                success: true,
                message: "Email verified successfully! Welcome to CyberCare."
            } 
        };
    }

    // Rescan email for breaches
    resource function post rescan\-breaches(@http:Header {name: "Authorization"} string? authHeader) returns http:Ok|http:Unauthorized|http:InternalServerError {
        if authHeader is () || !authHeader.startsWith("Bearer ") {
            return <http:Unauthorized>{ body: { success: false, message: "Authorization header required" } };
        }
        
        string token = authHeader.substring(7);
        
        string|error userId = jwt:getUserIdFromToken(token);
        if userId is error {
            return <http:Unauthorized>{ body: { success: false, message: "Invalid or expired token" } };
        }
        
        User|error? user = getUserById(userId);
        if user is error || user is () {
            return <http:Unauthorized>{ body: { success: false, message: "User not found" } };
        }
        
        // Perform breach scan
        BreachScanLog|error scanResult = hibp:checkEmailBreach(user.email, userId, "manual");
        if scanResult is error {
            log:printError("Failed to scan email: " + scanResult.message());
            return <http:InternalServerError>{ body: { success: false, message: "Failed to scan email for breaches" } };
        }
        
        return <http:Ok>{ 
            body: { 
                success: true,
                message: "Email scan completed",
                data: {
                    "scanResult": scanResult.scan_result,
                    "breachesFound": scanResult.breaches_found,
                    "scannedAt": scanResult.scanned_at
                }
            } 
        };
    }
}

// Helper functions

function checkUserExists(string email) returns boolean|error {
    sql:ParameterizedQuery query = `SELECT COUNT(*) as count FROM users WHERE email = ${email}`;
    
    stream<record {}, error?> resultStream = db:getConnection()->query(query);
    record {|record {} value;|}? result = check resultStream.next();
    check resultStream.close();
    
    if result is record {|record {} value;|} {
        int count = <int>result.value["count"];
        return count > 0;
    }
    
    return false;
}

function createUser(User user) returns error? {
    sql:ParameterizedQuery insertQuery = `
        INSERT INTO users (id, email, password_hash, name, email_verified, verification_token, created_at, updated_at, is_active)
        VALUES (${user.id}, ${user.email}, ${user.password_hash}, ${user.name}, ${user.email_verified}, 
                ${user.verification_token}, ${user.created_at}, ${user.updated_at}, ${user.is_active})
    `;
    
    sql:ExecutionResult|sql:Error result = db:getConnection()->execute(insertQuery);
    
    if result is sql:Error {
        return error("Failed to create user: " + result.message());
    }
}

function getUserByEmail(string email) returns User|error? {
    sql:ParameterizedQuery query = `
        SELECT id, email, password_hash, name, email_verified, verification_token, created_at, updated_at, last_login, is_active
        FROM users WHERE email = ${email}
    `;
    
    stream<record {}, error?> resultStream = db:getConnection()->query(query);
    record {|record {} value;|}? result = check resultStream.next();
    check resultStream.close();
    
    if result is record {|record {} value;|} {
        record {} userRecord = result.value;
        return {
            id: userRecord["id"].toString(),
            email: userRecord["email"].toString(),
            password_hash: userRecord["password_hash"].toString(),
            name: userRecord["name"].toString(),
            email_verified: <boolean>userRecord["email_verified"],
            verification_token: userRecord["verification_token"] != () ? userRecord["verification_token"].toString() : (),
            created_at: <time:Utc>userRecord["created_at"],
            updated_at: <time:Utc>userRecord["updated_at"],
            last_login: userRecord["last_login"] != () ? <time:Utc>userRecord["last_login"] : (),
            is_active: <boolean>userRecord["is_active"]
        };
    }
    
    return ();
}

function getUserById(string userId) returns User|error? {
    sql:ParameterizedQuery query = `
        SELECT id, email, password_hash, name, email_verified, verification_token, created_at, updated_at, last_login, is_active
        FROM users WHERE id = ${userId}
    `;
    
    stream<record {}, error?> resultStream = db:getConnection()->query(query);
    record {|record {} value;|}? result = check resultStream.next();
    check resultStream.close();
    
    if result is record {|record {} value;|} {
        record {} userRecord = result.value;
        return {
            id: userRecord["id"].toString(),
            email: userRecord["email"].toString(),
            password_hash: userRecord["password_hash"].toString(),
            name: userRecord["name"].toString(),
            email_verified: <boolean>userRecord["email_verified"],
            verification_token: userRecord["verification_token"] != () ? userRecord["verification_token"].toString() : (),
            created_at: <time:Utc>userRecord["created_at"],
            updated_at: <time:Utc>userRecord["updated_at"],
            last_login: userRecord["last_login"] != () ? <time:Utc>userRecord["last_login"] : (),
            is_active: <boolean>userRecord["is_active"]
        };
    }
    
    return ();
}

function getUserByVerificationToken(string token) returns User|error? {
    sql:ParameterizedQuery query = `
        SELECT id, email, password_hash, name, email_verified, verification_token, created_at, updated_at, last_login, is_active
        FROM users WHERE verification_token = ${token}
    `;
    
    stream<record {}, error?> resultStream = db:getConnection()->query(query);
    record {|record {} value;|}? result = check resultStream.next();
    check resultStream.close();
    
    if result is record {|record {} value;|} {
        record {} userRecord = result.value;
        return {
            id: userRecord["id"].toString(),
            email: userRecord["email"].toString(),
            password_hash: userRecord["password_hash"].toString(),
            name: userRecord["name"].toString(),
            email_verified: <boolean>userRecord["email_verified"],
            verification_token: userRecord["verification_token"] != () ? userRecord["verification_token"].toString() : (),
            created_at: <time:Utc>userRecord["created_at"],
            updated_at: <time:Utc>userRecord["updated_at"],
            last_login: userRecord["last_login"] != () ? <time:Utc>userRecord["last_login"] : (),
            is_active: <boolean>userRecord["is_active"]
        };
    }
    
    return ();
}

function updateLastLogin(string userId) returns error? {
    time:Utc currentTime = time:utcNow();
    
    sql:ParameterizedQuery updateQuery = `
        UPDATE users SET last_login = ${currentTime} WHERE id = ${userId}
    `;
    
    sql:ExecutionResult|sql:Error result = db:getConnection()->execute(updateQuery);
    
    if result is sql:Error {
        return error("Failed to update last login: " + result.message());
    }
}

function verifyUserEmail(string userId) returns error? {
    time:Utc currentTime = time:utcNow();
    
    sql:ParameterizedQuery updateQuery = `
        UPDATE users SET email_verified = true, verification_token = null, updated_at = ${currentTime} 
        WHERE id = ${userId}
    `;
    
    sql:ExecutionResult|sql:Error result = db:getConnection()->execute(updateQuery);
    
    if result is sql:Error {
        return error("Failed to verify email: " + result.message());
    }
}

function getAdminRole(string userId) returns string? {
    sql:ParameterizedQuery query = `SELECT role FROM admins WHERE user_id = ${userId}`;
    
    stream<record {}, error?> resultStream = db:getConnection()->query(query);
    record {|record {} value;|}|error? result = resultStream.next();
    error? closeResult = resultStream.close();
    
    if result is record {|record {} value;|} {
        return result.value["role"].toString();
    }
    
    return ();
}

function isValidEmail(string email) returns boolean {
    // Simple email validation
    return email.includes("@") && email.includes(".") && email.length() > 5;
}
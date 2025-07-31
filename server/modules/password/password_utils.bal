import ballerina/crypto;
import ballerina/random;
import ballerina/log;

// Configuration for password hashing
configurable string secret = ?;

// Salt length for password hashing
const int SALT_LENGTH = 16;

// Generate a random salt
function generateSalt() returns string|error {
    byte[] saltBytes = check random:createByteArray(SALT_LENGTH);
    return saltBytes.toBase64();
}

// Hash password with salt using PBKDF2
public function hashPassword(string password) returns string|error {
    string salt = check generateSalt();
    string saltedPassword = password + salt + secret;
    
    byte[] passwordBytes = saltedPassword.toBytes();
    byte[] hashedBytes = check crypto:hashSha256(passwordBytes);
    string hashedPassword = hashedBytes.toBase64();
    
    // Combine salt and hash (salt:hash format)
    return salt + ":" + hashedPassword;
}

// Verify password against stored hash
public function verifyPassword(string password, string storedHash) returns boolean|error {
    // Split salt and hash
    string[] parts = storedHash.split(":");
    if parts.length() != 2 {
        log:printError("Invalid password hash format");
        return false;
    }
    
    string salt = parts[0];
    string expectedHash = parts[1];
    
    // Hash the provided password with the same salt
    string saltedPassword = password + salt + secret;
    byte[] passwordBytes = saltedPassword.toBytes();
    byte[] hashedBytes = check crypto:hashSha256(passwordBytes);
    string actualHash = hashedBytes.toBase64();
    
    // Compare hashes
    return actualHash == expectedHash;
}

// Generate a secure random token for email verification
public function generateVerificationToken() returns string|error {
    byte[] tokenBytes = check random:createByteArray(32);
    return tokenBytes.toBase64();
}

// Validate password strength
public function validatePasswordStrength(string password) returns boolean {
    // Password must be at least 8 characters long
    if password.length() < 8 {
        return false;
    }
    
    // Check for at least one uppercase, one lowercase, one digit
    boolean hasUpper = false;
    boolean hasLower = false;
    boolean hasDigit = false;
    
    foreach int i in 0..<password.length() {
        string char = password.substring(i, i + 1);
        if char >= "A" && char <= "Z" {
            hasUpper = true;
        } else if char >= "a" && char <= "z" {
            hasLower = true;
        } else if char >= "0" && char <= "9" {
            hasDigit = true;
        }
    }
    
    return hasUpper && hasLower && hasDigit;
}
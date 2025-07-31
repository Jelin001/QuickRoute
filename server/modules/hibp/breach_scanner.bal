import ballerina/http;
import ballerina/log;
import ballerina/sql;
import ballerina/time;
import ballerina/uuid;
import cybercare_backend.db;

// HIBP API configuration
configurable string hibp_api_key = ?;
configurable string hibp_base_url = ?;

// HTTP client for HIBP API
http:Client hibpClient = check new (hibp_base_url, {
    timeout: 30,
    retryConfig: {
        count: 3,
        interval: 2
    }
});

// Check if email has been breached
public function checkEmailBreach(string email, string userId, ScanType scanType = "manual") returns BreachScanLog|error {
    log:printInfo(string `Scanning email for breaches: ${email}`);
    
    // Create scan log entry
    string scanId = uuid:createType1AsString();
    time:Utc scanTime = time:utcNow();
    
    try {
        // Make request to HIBP API
        map<string> headers = {
            "hibp-api-key": hibp_api_key,
            "User-Agent": "CyberCare-BreachScanner"
        };
        
        string endpoint = string `/breachedaccount/${email}?truncateResponse=false`;
        http:Response|http:ClientError response = hibpClient->get(endpoint, headers);
        
        if response is http:ClientError {
            log:printError(string `HIBP API error: ${response.message()}`);
            return createScanLog(scanId, userId, email, scanType, [], "error", (), scanTime);
        }
        
        if response.statusCode == 404 {
            // No breaches found - this is good!
            log:printInfo(string `No breaches found for email: ${email}`);
            return createScanLog(scanId, userId, email, scanType, [], "clean", (), scanTime);
        }
        
        if response.statusCode == 200 {
            // Breaches found
            json|http:ClientError breachData = response.getJsonPayload();
            
            if breachData is json {
                HIBPBreach[]|error breaches = parseBreachResponse(breachData);
                
                if breaches is HIBPBreach[] {
                    string[] breachNames = from HIBPBreach breach in breaches select breach.Name;
                    log:printInfo(string `Found ${breaches.length()} breaches for email: ${email}`);
                    
                    return createScanLog(scanId, userId, email, scanType, breachNames, "breached", breachData, scanTime);
                } else {
                    log:printError("Failed to parse HIBP response");
                    return createScanLog(scanId, userId, email, scanType, [], "error", (), scanTime);
                }
            } else {
                log:printError("Invalid JSON response from HIBP");
                return createScanLog(scanId, userId, email, scanType, [], "error", (), scanTime);
            }
        }
        
        // Handle rate limiting (429) or other errors
        if response.statusCode == 429 {
            log:printWarn("HIBP API rate limit exceeded");
            return error("Rate limit exceeded. Please try again later.");
        }
        
        log:printError(string `Unexpected HIBP API response: ${response.statusCode}`);
        return createScanLog(scanId, userId, email, scanType, [], "error", (), scanTime);
        
    } catch (error e) {
        log:printError(string `Error during breach scan: ${e.message()}`);
        return createScanLog(scanId, userId, email, scanType, [], "error", (), scanTime);
    }
}

// Parse HIBP breach response
function parseBreachResponse(json breachData) returns HIBPBreach[]|error {
    if breachData is json[] {
        HIBPBreach[] breaches = [];
        
        foreach json breachJson in breachData {
            if breachJson is map<json> {
                HIBPBreach breach = {
                    Name: breachJson.hasKey("Name") ? breachJson["Name"].toString() : "",
                    Title: breachJson.hasKey("Title") ? breachJson["Title"].toString() : "",
                    Domain: breachJson.hasKey("Domain") ? breachJson["Domain"].toString() : "",
                    BreachDate: breachJson.hasKey("BreachDate") ? breachJson["BreachDate"].toString() : "",
                    AddedDate: breachJson.hasKey("AddedDate") ? breachJson["AddedDate"].toString() : "",
                    ModifiedDate: breachJson.hasKey("ModifiedDate") ? breachJson["ModifiedDate"].toString() : "",
                    PwnCount: breachJson.hasKey("PwnCount") ? <int>breachJson["PwnCount"] : 0,
                    Description: breachJson.hasKey("Description") ? breachJson["Description"].toString() : "",
                    DataClasses: breachJson.hasKey("DataClasses") && breachJson["DataClasses"] is json[] ? 
                                from json dataClass in <json[]>breachJson["DataClasses"] select dataClass.toString() : [],
                    IsVerified: breachJson.hasKey("IsVerified") ? <boolean>breachJson["IsVerified"] : false,
                    IsFabricated: breachJson.hasKey("IsFabricated") ? <boolean>breachJson["IsFabricated"] : false,
                    IsSensitive: breachJson.hasKey("IsSensitive") ? <boolean>breachJson["IsSensitive"] : false,
                    IsRetired: breachJson.hasKey("IsRetired") ? <boolean>breachJson["IsRetired"] : false,
                    IsSpamList: breachJson.hasKey("IsSpamList") ? <boolean>breachJson["IsSpamList"] : false,
                    LogoPath: breachJson.hasKey("LogoPath") ? breachJson["LogoPath"].toString() : ""
                };
                breaches.push(breach);
            }
        }
        
        return breaches;
    }
    
    return error("Invalid breach data format");
}

// Create and store scan log in database
function createScanLog(string id, string userId, string email, ScanType scanType, 
                      string[] breachNames, ScanResult result, json? hibpResponse, time:Utc scanTime) returns BreachScanLog|error {
    
    // Create breach scan log record
    BreachScanLog scanLog = {
        id: id,
        user_id: userId,
        email: email,
        scan_type: scanType,
        breaches_found: breachNames.length() > 0 ? breachNames.toJson() : (),
        scan_result: result,
        hibp_response: hibpResponse,
        scanned_at: scanTime,
        notified: false
    };
    
    // Store in database
    sql:ParameterizedQuery insertQuery = `
        INSERT INTO breach_scan_logs (id, user_id, email, scan_type, breaches_found, scan_result, hibp_response, scanned_at, notified)
        VALUES (${id}, ${userId}, ${email}, ${scanType}, ${scanLog.breaches_found}, ${result}, ${hibpResponse}, ${scanTime}, false)
    `;
    
    sql:ExecutionResult|sql:Error result2 = db:getConnection()->execute(insertQuery);
    
    if result2 is sql:Error {
        log:printError(string `Failed to store scan log: ${result2.message()}`);
        return error("Failed to store scan results");
    }
    
    log:printInfo(string `Scan log stored successfully for email: ${email}`);
    return scanLog;
}

// Get breach history for a user
public function getUserBreachHistory(string userId) returns BreachScanLog[]|error {
    sql:ParameterizedQuery query = `
        SELECT id, user_id, email, scan_type, breaches_found, scan_result, hibp_response, scanned_at, notified
        FROM breach_scan_logs 
        WHERE user_id = ${userId} 
        ORDER BY scanned_at DESC
    `;
    
    stream<record {}, error?> resultStream = db:getConnection()->query(query);
    BreachScanLog[] scanLogs = [];
    
    check from record {} scanRecord in resultStream
        do {
            BreachScanLog scanLog = {
                id: scanRecord["id"].toString(),
                user_id: scanRecord["user_id"].toString(),
                email: scanRecord["email"].toString(),
                scan_type: <ScanType>scanRecord["scan_type"],
                breaches_found: scanRecord["breaches_found"],
                scan_result: <ScanResult>scanRecord["scan_result"],
                hibp_response: scanRecord["hibp_response"],
                scanned_at: <time:Utc>scanRecord["scanned_at"],
                notified: <boolean>scanRecord["notified"]
            };
            scanLogs.push(scanLog);
        };
    
    check resultStream.close();
    return scanLogs;
}

// Get latest scan for an email
public function getLatestScanForEmail(string email) returns BreachScanLog?|error {
    sql:ParameterizedQuery query = `
        SELECT id, user_id, email, scan_type, breaches_found, scan_result, hibp_response, scanned_at, notified
        FROM breach_scan_logs 
        WHERE email = ${email} 
        ORDER BY scanned_at DESC 
        LIMIT 1
    `;
    
    stream<record {}, error?> resultStream = db:getConnection()->query(query);
    record {|record {} value;|}? result = check resultStream.next();
    check resultStream.close();
    
    if result is record {|record {} value;|} {
        record {} scanRecord = result.value;
        return {
            id: scanRecord["id"].toString(),
            user_id: scanRecord["user_id"].toString(),
            email: scanRecord["email"].toString(),
            scan_type: <ScanType>scanRecord["scan_type"],
            breaches_found: scanRecord["breaches_found"],
            scan_result: <ScanResult>scanRecord["scan_result"],
            hibp_response: scanRecord["hibp_response"],
            scanned_at: <time:Utc>scanRecord["scanned_at"],
            notified: <boolean>scanRecord["notified"]
        };
    }
    
    return ();
}

// Mark scan as notified
public function markScanAsNotified(string scanId) returns error? {
    sql:ParameterizedQuery updateQuery = `
        UPDATE breach_scan_logs 
        SET notified = true 
        WHERE id = ${scanId}
    `;
    
    sql:ExecutionResult|sql:Error result = db:getConnection()->execute(updateQuery);
    
    if result is sql:Error {
        log:printError(string `Failed to mark scan as notified: ${result.message()}`);
        return error("Failed to update scan notification status");
    }
    
    log:printInfo(string `Scan marked as notified: ${scanId}`);
}

// Get unnotified breached scans
public function getUnnotifiedBreaches() returns BreachScanLog[]|error {
    sql:ParameterizedQuery query = `
        SELECT id, user_id, email, scan_type, breaches_found, scan_result, hibp_response, scanned_at, notified
        FROM breach_scan_logs 
        WHERE scan_result = 'breached' AND notified = false
        ORDER BY scanned_at ASC
    `;
    
    stream<record {}, error?> resultStream = db:getConnection()->query(query);
    BreachScanLog[] scanLogs = [];
    
    check from record {} scanRecord in resultStream
        do {
            BreachScanLog scanLog = {
                id: scanRecord["id"].toString(),
                user_id: scanRecord["user_id"].toString(),
                email: scanRecord["email"].toString(),
                scan_type: <ScanType>scanRecord["scan_type"],
                breaches_found: scanRecord["breaches_found"],
                scan_result: <ScanResult>scanRecord["scan_result"],
                hibp_response: scanRecord["hibp_response"],
                scanned_at: <time:Utc>scanRecord["scanned_at"],
                notified: <boolean>scanRecord["notified"]
            };
            scanLogs.push(scanLog);
        };
    
    check resultStream.close();
    return scanLogs;
}

// Test HIBP API connectivity
public function testHIBPConnection() returns boolean {
    try {
        map<string> headers = {
            "hibp-api-key": hibp_api_key,
            "User-Agent": "CyberCare-BreachScanner-Test"
        };
        
        // Test with a known breached email for testing
        http:Response|http:ClientError response = hibpClient->get("/breachedaccount/test@example.com", headers);
        
        if response is http:Response {
            // Any response (200, 404, etc.) means the API is reachable
            return true;
        }
        
        return false;
    } catch (error e) {
        log:printError(string `HIBP connection test failed: ${e.message()}`);
        return false;
    }
}
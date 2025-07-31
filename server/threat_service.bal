import ballerina/http;
import ballerina/log;
import ballerina/sql;
import ballerina/time;
import ballerina/uuid;
import cybercare_backend.db;
import cybercare_backend.jwt;
import cybercare_backend.virustotal as vt;

// Threat reporting service
service /threats on new http:Listener(8080) {

    // Submit a new threat report
    resource function post reports(@http:Header {name: "Authorization"} string? authHeader, ThreatReportSubmission reportData) 
            returns http:Created|http:BadRequest|http:Unauthorized|http:InternalServerError {
        
        // Authenticate user
        string|error userId = authenticateUser(authHeader);
        if userId is error {
            return <http:Unauthorized>{ body: { success: false, message: userId.message() } };
        }
        
        // Validate input
        if reportData.title.trim() == "" || reportData.description.trim() == "" {
            return <http:BadRequest>{ body: { success: false, message: "Title and description are required" } };
        }
        
        // Create threat report
        string reportId = uuid:createType1AsString();
        time:Utc currentTime = time:utcNow();
        
        ThreatReport report = {
            id: reportId,
            title: reportData.title,
            description: reportData.description,
            links: reportData.links is string[] ? reportData.links.toJson() : (),
            evidence: reportData.evidence,
            evidence_type: reportData.evidence_type,
            submitted_by: userId,
            status: "pending",
            priority: reportData.priority,
            category: reportData.category,
            submitted_at: currentTime,
            updated_at: currentTime
        };
        
        // Store report in database
        error? createResult = createThreatReport(report);
        if createResult is error {
            log:printError("Failed to create threat report: " + createResult.message());
            return <http:InternalServerError>{ body: { success: false, message: "Failed to submit threat report" } };
        }
        
        // Start VirusTotal scanning asynchronously if links are provided
        worker virusTotalWorker {
            if reportData.links is string[] && reportData.links.length() > 0 {
                VirusTotalScan[]|error scanResults = vt:scanThreatReportURLs(reportId, reportData.description, reportData.links);
                if scanResults is error {
                    log:printError("VirusTotal scanning failed: " + scanResults.message());
                } else {
                    log:printInfo(string `VirusTotal scans completed for report: ${reportId}`);
                    
                    // Auto-update threat status based on scan results
                    ThreatStatus autoStatus = vt:determineThreatLevel(scanResults);
                    if autoStatus != "needs_review" {
                        error? updateResult = updateThreatStatus(reportId, autoStatus, "Automatically determined by VirusTotal scan results", "system");
                        if updateResult is error {
                            log:printError("Failed to auto-update threat status: " + updateResult.message());
                        }
                    }
                }
            }
        }
        
        log:printInfo(string `Threat report submitted: ${reportId} by user: ${userId}`);
        
        return <http:Created>{ 
            body: { 
                success: true,
                message: "Threat report submitted successfully",
                data: {
                    "reportId": reportId,
                    "status": "pending",
                    "submittedAt": currentTime
                }
            }
        };
    }

    // Get user's threat reports
    resource function get reports(@http:Header {name: "Authorization"} string? authHeader, 
                                 int? page = 1, int? limit = 10) 
            returns http:Ok|http:Unauthorized|http:InternalServerError {
        
        string|error userId = authenticateUser(authHeader);
        if userId is error {
            return <http:Unauthorized>{ body: { success: false, message: userId.message() } };
        }
        
        int pageNum = page ?: 1;
        int limitNum = limit ?: 10;
        int offset = (pageNum - 1) * limitNum;
        
        ThreatReport[]|error reports = getUserThreatReports(userId, limitNum, offset);
        if reports is error {
            log:printError("Failed to get user reports: " + reports.message());
            return <http:InternalServerError>{ body: { success: false, message: "Failed to retrieve threat reports" } };
        }
        
        int|error totalCount = getUserThreatReportsCount(userId);
        if totalCount is error {
            log:printError("Failed to get reports count: " + totalCount.message());
            totalCount = 0;
        }
        
        int totalPages = (totalCount + limitNum - 1) / limitNum;
        
        return <http:Ok>{ 
            body: { 
                success: true,
                data: reports,
                pagination: {
                    "page": pageNum,
                    "limit": limitNum,
                    "total": totalCount,
                    "totalPages": totalPages
                }
            }
        };
    }

    // Get specific threat report details
    resource function get reports/[string reportId](@http:Header {name: "Authorization"} string? authHeader) 
            returns http:Ok|http:Unauthorized|http:NotFound|http:InternalServerError {
        
        string|error userId = authenticateUser(authHeader);
        if userId is error {
            return <http:Unauthorized>{ body: { success: false, message: userId.message() } };
        }
        
        ThreatReport|error? report = getThreatReportById(reportId);
        if report is error {
            log:printError("Failed to get threat report: " + report.message());
            return <http:InternalServerError>{ body: { success: false, message: "Failed to retrieve threat report" } };
        }
        
        if report is () {
            return <http:NotFound>{ body: { success: false, message: "Threat report not found" } };
        }
        
        // Check if user is the owner or an admin
        boolean isOwner = report.submitted_by == userId;
        boolean|error isAdmin = checkIfUserIsAdmin(userId);
        if isAdmin is error {
            isAdmin = false;
        }
        
        if !isOwner && !isAdmin {
            return <http:Unauthorized>{ body: { success: false, message: "Access denied" } };
        }
        
        // Get VirusTotal scan results
        VirusTotalScan[]|error scanResults = vt:getScanResultsForReport(reportId);
        if scanResults is error {
            log:printWarn("Failed to get scan results: " + scanResults.message());
            scanResults = [];
        }
        
        json reportDetails = {
            "report": report,
            "virusTotalScans": scanResults,
            "scanSummary": scanResults.length() > 0 ? vt:getScanSummary(reportId) : ()
        };
        
        return <http:Ok>{ 
            body: { 
                success: true,
                data: reportDetails
            }
        };
    }

    // Get all threat reports (admin only)
    resource function get admin/reports(@http:Header {name: "Authorization"} string? authHeader,
                                       string? status = (), string? category = (), 
                                       int? page = 1, int? limit = 20) 
            returns http:Ok|http:Unauthorized|http:Forbidden|http:InternalServerError {
        
        string|error userId = authenticateUser(authHeader);
        if userId is error {
            return <http:Unauthorized>{ body: { success: false, message: userId.message() } };
        }
        
        boolean|error isAdmin = checkIfUserIsAdmin(userId);
        if isAdmin is error || !isAdmin {
            return <http:Forbidden>{ body: { success: false, message: "Admin access required" } };
        }
        
        int pageNum = page ?: 1;
        int limitNum = limit ?: 20;
        int offset = (pageNum - 1) * limitNum;
        
        ThreatReport[]|error reports = getAllThreatReports(status, category, limitNum, offset);
        if reports is error {
            log:printError("Failed to get all reports: " + reports.message());
            return <http:InternalServerError>{ body: { success: false, message: "Failed to retrieve threat reports" } };
        }
        
        int|error totalCount = getAllThreatReportsCount(status, category);
        if totalCount is error {
            totalCount = 0;
        }
        
        int totalPages = (totalCount + limitNum - 1) / limitNum;
        
        return <http:Ok>{ 
            body: { 
                success: true,
                data: reports,
                pagination: {
                    "page": pageNum,
                    "limit": limitNum,
                    "total": totalCount,
                    "totalPages": totalPages
                }
            }
        };
    }

    // Update threat report status (admin only)
    resource function put reports/[string reportId]/status(@http:Header {name: "Authorization"} string? authHeader,
                                                          ThreatReportUpdate updateData) 
            returns http:Ok|http:Unauthorized|http:Forbidden|http:NotFound|http:InternalServerError {
        
        string|error userId = authenticateUser(authHeader);
        if userId is error {
            return <http:Unauthorized>{ body: { success: false, message: userId.message() } };
        }
        
        boolean|error isAdmin = checkIfUserIsAdmin(userId);
        if isAdmin is error || !isAdmin {
            return <http:Forbidden>{ body: { success: false, message: "Admin access required" } };
        }
        
        // Check if report exists
        ThreatReport|error? report = getThreatReportById(reportId);
        if report is error {
            return <http:InternalServerError>{ body: { success: false, message: "Failed to retrieve threat report" } };
        }
        
        if report is () {
            return <http:NotFound>{ body: { success: false, message: "Threat report not found" } };
        }
        
        // Update threat status
        error? updateResult = updateThreatStatus(reportId, updateData.status, updateData.validation_remarks, userId);
        if updateResult is error {
            log:printError("Failed to update threat status: " + updateResult.message());
            return <http:InternalServerError>{ body: { success: false, message: "Failed to update threat report" } };
        }
        
        // Send notification to user about status update
        worker notificationWorker {
            User|error? reportOwner = getUserById(report.submitted_by);
            if reportOwner is User {
                error? emailResult = email:sendThreatReportUpdate(
                    reportOwner.email, 
                    reportOwner.name, 
                    report.title, 
                    updateData.status, 
                    updateData.validation_remarks
                );
                if emailResult is error {
                    log:printWarn("Failed to send status update email: " + emailResult.message());
                }
            }
        }
        
        log:printInfo(string `Threat report ${reportId} status updated to ${updateData.status} by admin ${userId}`);
        
        return <http:Ok>{ 
            body: { 
                success: true,
                message: "Threat report status updated successfully"
            }
        };
    }

    // Get threat statistics
    resource function get stats(@http:Header {name: "Authorization"} string? authHeader) 
            returns http:Ok|http:Unauthorized|http:InternalServerError {
        
        string|error userId = authenticateUser(authHeader);
        if userId is error {
            return <http:Unauthorized>{ body: { success: false, message: userId.message() } };
        }
        
        json|error stats = getThreatStatistics();
        if stats is error {
            log:printError("Failed to get threat statistics: " + stats.message());
            return <http:InternalServerError>{ body: { success: false, message: "Failed to retrieve statistics" } };
        }
        
        return <http:Ok>{ 
            body: { 
                success: true,
                data: stats
            }
        };
    }
}

// Helper functions

function authenticateUser(string? authHeader) returns string|error {
    if authHeader is () || !authHeader.startsWith("Bearer ") {
        return error("Authorization header required");
    }
    
    string token = authHeader.substring(7);
    return jwt:getUserIdFromToken(token);
}

function createThreatReport(ThreatReport report) returns error? {
    sql:ParameterizedQuery insertQuery = `
        INSERT INTO threat_reports (id, title, description, links, evidence, evidence_type, submitted_by, 
                                   status, priority, category, submitted_at, updated_at)
        VALUES (${report.id}, ${report.title}, ${report.description}, ${report.links}, ${report.evidence}, 
                ${report.evidence_type}, ${report.submitted_by}, ${report.status}, ${report.priority}, 
                ${report.category}, ${report.submitted_at}, ${report.updated_at})
    `;
    
    sql:ExecutionResult|sql:Error result = db:getConnection()->execute(insertQuery);
    
    if result is sql:Error {
        return error("Failed to create threat report: " + result.message());
    }
}

function getUserThreatReports(string userId, int limit, int offset) returns ThreatReport[]|error {
    sql:ParameterizedQuery query = `
        SELECT id, title, description, links, evidence, evidence_type, submitted_by, status, priority, category,
               submitted_at, updated_at, validated_by, validated_at, validation_remarks, escalated_to_cert, escalated_at
        FROM threat_reports 
        WHERE submitted_by = ${userId}
        ORDER BY submitted_at DESC
        LIMIT ${limit} OFFSET ${offset}
    `;
    
    return executeReportQuery(query);
}

function getUserThreatReportsCount(string userId) returns int|error {
    sql:ParameterizedQuery query = `SELECT COUNT(*) as count FROM threat_reports WHERE submitted_by = ${userId}`;
    
    stream<record {}, error?> resultStream = db:getConnection()->query(query);
    record {|record {} value;|}? result = check resultStream.next();
    check resultStream.close();
    
    if result is record {|record {} value;|} {
        return <int>result.value["count"];
    }
    
    return 0;
}

function getAllThreatReports(string? status, string? category, int limit, int offset) returns ThreatReport[]|error {
    string whereClause = "";
    if status is string {
        whereClause += string ` WHERE status = '${status}'`;
    }
    if category is string {
        if whereClause == "" {
            whereClause += string ` WHERE category = '${category}'`;
        } else {
            whereClause += string ` AND category = '${category}'`;
        }
    }
    
    sql:ParameterizedQuery query = sql:queryConcat(`
        SELECT id, title, description, links, evidence, evidence_type, submitted_by, status, priority, category,
               submitted_at, updated_at, validated_by, validated_at, validation_remarks, escalated_to_cert, escalated_at
        FROM threat_reports`, 
        sql:queryConcat(whereClause, ` ORDER BY submitted_at DESC LIMIT ${limit} OFFSET ${offset}`)
    );
    
    return executeReportQuery(query);
}

function getAllThreatReportsCount(string? status, string? category) returns int|error {
    string whereClause = "";
    if status is string {
        whereClause += string ` WHERE status = '${status}'`;
    }
    if category is string {
        if whereClause == "" {
            whereClause += string ` WHERE category = '${category}'`;
        } else {
            whereClause += string ` AND category = '${category}'`;
        }
    }
    
    sql:ParameterizedQuery query = sql:queryConcat(`SELECT COUNT(*) as count FROM threat_reports`, whereClause);
    
    stream<record {}, error?> resultStream = db:getConnection()->query(query);
    record {|record {} value;|}? result = check resultStream.next();
    check resultStream.close();
    
    if result is record {|record {} value;|} {
        return <int>result.value["count"];
    }
    
    return 0;
}

function executeReportQuery(sql:ParameterizedQuery query) returns ThreatReport[]|error {
    stream<record {}, error?> resultStream = db:getConnection()->query(query);
    ThreatReport[] reports = [];
    
    check from record {} reportRecord in resultStream
        do {
            ThreatReport report = {
                id: reportRecord["id"].toString(),
                title: reportRecord["title"].toString(),
                description: reportRecord["description"].toString(),
                links: reportRecord["links"],
                evidence: reportRecord["evidence"] != () ? reportRecord["evidence"].toString() : (),
                evidence_type: <EvidenceType>reportRecord["evidence_type"],
                submitted_by: reportRecord["submitted_by"].toString(),
                status: <ThreatStatus>reportRecord["status"],
                priority: <Priority>reportRecord["priority"],
                category: <ThreatCategory>reportRecord["category"],
                submitted_at: <time:Utc>reportRecord["submitted_at"],
                updated_at: <time:Utc>reportRecord["updated_at"],
                validated_by: reportRecord["validated_by"] != () ? reportRecord["validated_by"].toString() : (),
                validated_at: reportRecord["validated_at"] != () ? <time:Utc>reportRecord["validated_at"] : (),
                validation_remarks: reportRecord["validation_remarks"] != () ? reportRecord["validation_remarks"].toString() : (),
                escalated_to_cert: <boolean>reportRecord["escalated_to_cert"],
                escalated_at: reportRecord["escalated_at"] != () ? <time:Utc>reportRecord["escalated_at"] : ()
            };
            reports.push(report);
        };
    
    check resultStream.close();
    return reports;
}

function getThreatReportById(string reportId) returns ThreatReport|error? {
    sql:ParameterizedQuery query = `
        SELECT id, title, description, links, evidence, evidence_type, submitted_by, status, priority, category,
               submitted_at, updated_at, validated_by, validated_at, validation_remarks, escalated_to_cert, escalated_at
        FROM threat_reports 
        WHERE id = ${reportId}
    `;
    
    ThreatReport[] reports = check executeReportQuery(query);
    
    if reports.length() > 0 {
        return reports[0];
    }
    
    return ();
}

function updateThreatStatus(string reportId, ThreatStatus status, string? remarks, string validatedBy) returns error? {
    time:Utc currentTime = time:utcNow();
    
    sql:ParameterizedQuery updateQuery = `
        UPDATE threat_reports 
        SET status = ${status}, validated_by = ${validatedBy}, validated_at = ${currentTime}, 
            validation_remarks = ${remarks}, updated_at = ${currentTime}
        WHERE id = ${reportId}
    `;
    
    sql:ExecutionResult|sql:Error result = db:getConnection()->execute(updateQuery);
    
    if result is sql:Error {
        return error("Failed to update threat status: " + result.message());
    }
}

function checkIfUserIsAdmin(string userId) returns boolean|error {
    sql:ParameterizedQuery query = `SELECT COUNT(*) as count FROM admins WHERE user_id = ${userId}`;
    
    stream<record {}, error?> resultStream = db:getConnection()->query(query);
    record {|record {} value;|}? result = check resultStream.next();
    check resultStream.close();
    
    if result is record {|record {} value;|} {
        int count = <int>result.value["count"];
        return count > 0;
    }
    
    return false;
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

function getThreatStatistics() returns json|error {
    sql:ParameterizedQuery statsQuery = `
        SELECT 
            COUNT(*) as total_reports,
            COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_reports,
            COUNT(CASE WHEN status = 'validated' THEN 1 END) as validated_reports,
            COUNT(CASE WHEN status = 'false_alarm' THEN 1 END) as false_alarms,
            COUNT(CASE WHEN status = 'escalated' THEN 1 END) as escalated_reports,
            COUNT(CASE WHEN category = 'phishing' THEN 1 END) as phishing_reports,
            COUNT(CASE WHEN category = 'malware' THEN 1 END) as malware_reports,
            COUNT(CASE WHEN category = 'scam' THEN 1 END) as scam_reports
        FROM threat_reports
    `;
    
    stream<record {}, error?> resultStream = db:getConnection()->query(statsQuery);
    record {|record {} value;|}? result = check resultStream.next();
    check resultStream.close();
    
    if result is record {|record {} value;|} {
        return result.value.toJson();
    }
    
    return {};
}
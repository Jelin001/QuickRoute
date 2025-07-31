import ballerina/http;
import ballerina/log;
import ballerina/sql;
import ballerina/time;
import ballerina/uuid;
import ballerina/regex;
import ballerina/runtime;
import cybercare_backend.db;

// VirusTotal API configuration
configurable string virustotal_api_key = ?;
configurable string virustotal_base_url = ?;

// HTTP client for VirusTotal API
http:Client vtClient = check new (virustotal_base_url, {
    timeout: 60,
    retryConfig: {
        count: 3,
        interval: 5
    }
});

// Scan URL through VirusTotal
public function scanURL(string url, string reportId) returns VirusTotalScan|error {
    log:printInfo(string `Scanning URL through VirusTotal: ${url}`);
    
    string scanId = uuid:createType1AsString();
    time:Utc scanTime = time:utcNow();
    
    try {
        // Submit URL for scanning
        string urlId = check submitURLForScanning(url);
        
        // Wait and get scan results
        json scanResults = check getScanResults(urlId);
        
        // Parse results
        VirusTotalScan scan = check parseScanResults(scanId, reportId, url, scanResults, scanTime);
        
        // Store in database
        check storeScanResults(scan);
        
        return scan;
    } catch (error e) {
        log:printError(string `VirusTotal scan error: ${e.message()}`);
        
        // Create error scan result
        VirusTotalScan errorScan = {
            id: scanId,
            report_id: reportId,
            url_or_hash: url,
            scan_type: "url",
            positives: 0,
            total_engines: 0,
            scan_date: scanTime,
            verdict: "error",
            result_details: {"error": e.message()}
        };
        
        check storeScanResults(errorScan);
        return errorScan;
    }
}

// Submit URL to VirusTotal for scanning
function submitURLForScanning(string url) returns string|error {
    map<string> headers = {
        "x-apikey": virustotal_api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    };
    
    string payload = string `url=${url}`;
    
    http:Response|http:ClientError response = vtClient->post("/urls", payload, headers);
    
    if response is http:ClientError {
        return error(string `Failed to submit URL: ${response.message()}`);
    }
    
    if response.statusCode == 200 {
        json|http:ClientError responseData = response.getJsonPayload();
        
        if responseData is json && responseData is map<json> {
            if responseData.hasKey("data") && responseData["data"] is map<json> {
                map<json> data = <map<json>>responseData["data"];
                if data.hasKey("id") {
                    return data["id"].toString();
                }
            }
        }
    }
    
    return error("Failed to get scan ID from VirusTotal");
}

// Get scan results from VirusTotal
function getScanResults(string urlId) returns json|error {
    map<string> headers = {
        "x-apikey": virustotal_api_key
    };
    
    // Poll for results (may take some time)
    int maxAttempts = 10;
    int attempt = 0;
    
    while attempt < maxAttempts {
        http:Response|http:ClientError response = vtClient->get(string `/urls/${urlId}`, headers);
        
        if response is http:ClientError {
            return error(string `Failed to get scan results: ${response.message()}`);
        }
        
        if response.statusCode == 200 {
            json|http:ClientError responseData = response.getJsonPayload();
            
            if responseData is json && responseData is map<json> {
                if responseData.hasKey("data") && responseData["data"] is map<json> {
                    map<json> data = <map<json>>responseData["data"];
                    
                    // Check if scan is complete
                    if data.hasKey("attributes") && data["attributes"] is map<json> {
                        map<json> attributes = <map<json>>data["attributes"];
                        
                        if attributes.hasKey("last_analysis_stats") {
                            return responseData;
                        }
                    }
                }
            }
        }
        
        // Wait before next attempt
        runtime:sleep(5);
        attempt += 1;
    }
    
    return error("Scan timeout - results not available");
}

// Parse VirusTotal scan results
function parseScanResults(string scanId, string reportId, string url, json scanData, time:Utc scanTime) returns VirusTotalScan|error {
    if scanData is map<json> && scanData.hasKey("data") && scanData["data"] is map<json> {
        map<json> data = <map<json>>scanData["data"];
        
        if data.hasKey("attributes") && data["attributes"] is map<json> {
            map<json> attributes = <map<json>>data["attributes"];
            
            if attributes.hasKey("last_analysis_stats") && attributes["last_analysis_stats"] is map<json> {
                map<json> stats = <map<json>>attributes["last_analysis_stats"];
                
                int malicious = stats.hasKey("malicious") ? <int>stats["malicious"] : 0;
                int suspicious = stats.hasKey("suspicious") ? <int>stats["suspicious"] : 0;
                int harmless = stats.hasKey("harmless") ? <int>stats["harmless"] : 0;
                int undetected = stats.hasKey("undetected") ? <int>stats["undetected"] : 0;
                
                int positives = malicious + suspicious;
                int totalEngines = malicious + suspicious + harmless + undetected;
                
                // Determine verdict
                VirusTotalVerdict verdict = "clean";
                if malicious > 3 {
                    verdict = "malicious";
                } else if malicious > 0 || suspicious > 2 {
                    verdict = "suspicious";
                }
                
                // Get permalink if available
                string? permalink = ();
                if data.hasKey("links") && data["links"] is map<json> {
                    map<json> links = <map<json>>data["links"];
                    if links.hasKey("self") {
                        permalink = links["self"].toString();
                    }
                }
                
                return {
                    id: scanId,
                    report_id: reportId,
                    url_or_hash: url,
                    scan_type: "url",
                    positives: positives,
                    total_engines: totalEngines,
                    scan_date: scanTime,
                    result_details: scanData,
                    verdict: verdict,
                    permalink: permalink
                };
            }
        }
    }
    
    return error("Invalid scan results format");
}

// Store scan results in database
function storeScanResults(VirusTotalScan scan) returns error? {
    sql:ParameterizedQuery insertQuery = `
        INSERT INTO virustotal_scans (id, report_id, url_or_hash, scan_type, positives, total_engines, 
                                     scan_date, result_details, verdict, permalink)
        VALUES (${scan.id}, ${scan.report_id}, ${scan.url_or_hash}, ${scan.scan_type}, ${scan.positives}, 
                ${scan.total_engines}, ${scan.scan_date}, ${scan.result_details}, ${scan.verdict}, ${scan.permalink})
    `;
    
    sql:ExecutionResult|sql:Error result = db:getConnection()->execute(insertQuery);
    
    if result is sql:Error {
        log:printError(string `Failed to store VirusTotal scan: ${result.message()}`);
        return error("Failed to store scan results");
    }
    
    log:printInfo(string `VirusTotal scan stored: ${scan.id}`);
}

// Extract URLs from threat report text
public function extractURLsFromText(string text) returns string[] {
    string[] urls = [];
    
    // URL regex pattern
    string urlPattern = "https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+";
    
    string:RegExp|error urlRegex = regex:fromString(urlPattern);
    
    if urlRegex is string:RegExp {
        regex:Span[]|error matches = urlRegex.findAll(text);
        
        if matches is regex:Span[] {
            foreach regex:Span match in matches {
                string url = text.substring(match.startIndex, match.endIndex);
                urls.push(url);
            }
        }
    }
    
    return urls;
}

// Scan multiple URLs from a threat report
public function scanThreatReportURLs(string reportId, string description, string[]? providedLinks = ()) returns VirusTotalScan[]|error {
    string[] urlsToScan = [];
    
    // Add provided links
    if providedLinks is string[] {
        urlsToScan.push(...providedLinks);
    }
    
    // Extract URLs from description
    string[] extractedUrls = extractURLsFromText(description);
    urlsToScan.push(...extractedUrls);
    
    // Remove duplicates
    string[] uniqueUrls = [];
    foreach string url in urlsToScan {
        if uniqueUrls.indexOf(url) == () {
            uniqueUrls.push(url);
        }
    }
    
    log:printInfo(string `Found ${uniqueUrls.length()} URLs to scan for report: ${reportId}`);
    
    VirusTotalScan[] scans = [];
    
    // Scan each URL (with rate limiting consideration)
    foreach int i in 0..<uniqueUrls.length() {
        if i > 0 {
            // Add delay between requests to respect rate limits
            runtime:sleep(15); // 15 seconds between requests
        }
        
        VirusTotalScan|error scan = scanURL(uniqueUrls[i], reportId);
        
        if scan is VirusTotalScan {
            scans.push(scan);
        } else {
            log:printError(string `Failed to scan URL ${uniqueUrls[i]}: ${scan.message()}`);
        }
    }
    
    return scans;
}

// Get scan results for a threat report
public function getScanResultsForReport(string reportId) returns VirusTotalScan[]|error {
    sql:ParameterizedQuery query = `
        SELECT id, report_id, url_or_hash, scan_type, scan_id, positives, total_engines, 
               scan_date, result_details, verdict, permalink
        FROM virustotal_scans 
        WHERE report_id = ${reportId}
        ORDER BY scan_date DESC
    `;
    
    stream<record {}, error?> resultStream = db:getConnection()->query(query);
    VirusTotalScan[] scans = [];
    
    check from record {} scanRecord in resultStream
        do {
            VirusTotalScan scan = {
                id: scanRecord["id"].toString(),
                report_id: scanRecord["report_id"].toString(),
                url_or_hash: scanRecord["url_or_hash"].toString(),
                scan_type: <VirusTotalScanType>scanRecord["scan_type"],
                scan_id: scanRecord["scan_id"] != () ? scanRecord["scan_id"].toString() : (),
                positives: <int>scanRecord["positives"],
                total_engines: <int>scanRecord["total_engines"],
                scan_date: <time:Utc>scanRecord["scan_date"],
                result_details: scanRecord["result_details"],
                verdict: <VirusTotalVerdict>scanRecord["verdict"],
                permalink: scanRecord["permalink"] != () ? scanRecord["permalink"].toString() : ()
            };
            scans.push(scan);
        };
    
    check resultStream.close();
    return scans;
}

// Determine overall threat level based on scan results
public function determineThreatLevel(VirusTotalScan[] scans) returns ThreatStatus {
    if scans.length() == 0 {
        return "needs_review";
    }
    
    int maliciousCount = 0;
    int suspiciousCount = 0;
    int totalScans = scans.length();
    
    foreach VirusTotalScan scan in scans {
        if scan.verdict == "malicious" {
            maliciousCount += 1;
        } else if scan.verdict == "suspicious" {
            suspiciousCount += 1;
        }
    }
    
    // Decision logic
    if maliciousCount > 0 {
        return "validated"; // At least one URL is confirmed malicious
    } else if suspiciousCount > 0 {
        return "needs_review"; // Some suspicious URLs, needs manual review
    } else {
        return "false_alarm"; // All URLs are clean
    }
}

// Get VirusTotal scan summary for reporting
public function getScanSummary(string reportId) returns json|error {
    VirusTotalScan[] scans = check getScanResultsForReport(reportId);
    
    int totalScans = scans.length();
    int maliciousCount = 0;
    int suspiciousCount = 0;
    int cleanCount = 0;
    int errorCount = 0;
    
    foreach VirusTotalScan scan in scans {
        match scan.verdict {
            "malicious" => { maliciousCount += 1; }
            "suspicious" => { suspiciousCount += 1; }
            "clean" => { cleanCount += 1; }
            "error" => { errorCount += 1; }
        }
    }
    
    return {
        "reportId": reportId,
        "totalScans": totalScans,
        "malicious": maliciousCount,
        "suspicious": suspiciousCount,
        "clean": cleanCount,
        "errors": errorCount,
        "overallThreatLevel": determineThreatLevel(scans),
        "scanDetails": scans.map(scan => {
            "url": scan.url_or_hash,
            "verdict": scan.verdict,
            "positives": scan.positives,
            "totalEngines": scan.total_engines,
            "scanDate": scan.scan_date
        })
    };
}

// Test VirusTotal API connectivity
public function testVirusTotalConnection() returns boolean {
    try {
        map<string> headers = {
            "x-apikey": virustotal_api_key
        };
        
        // Test with a simple API call
        http:Response|http:ClientError response = vtClient->get("/urls/limits", headers);
        
        if response is http:Response && response.statusCode == 200 {
            return true;
        }
        
        return false;
    } catch (error e) {
        log:printError(string `VirusTotal connection test failed: ${e.message()}`);
        return false;
    }
}

// Clean up old scan results (for maintenance)
public function cleanupOldScans(int daysToKeep = 90) returns error? {
    time:Utc cutoffTime = time:utcAddSeconds(time:utcNow(), -(daysToKeep * 24 * 60 * 60));
    
    sql:ParameterizedQuery deleteQuery = `
        DELETE FROM virustotal_scans 
        WHERE scan_date < ${cutoffTime}
    `;
    
    sql:ExecutionResult|sql:Error result = db:getConnection()->execute(deleteQuery);
    
    if result is sql:Error {
        log:printError(string `Failed to cleanup old scans: ${result.message()}`);
        return error("Failed to cleanup old scan results");
    }
    
    if result is sql:ExecutionResult {
        log:printInfo(string `Cleaned up ${result.affectedRowCount} old scan records`);
    }
}
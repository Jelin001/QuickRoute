import ballerina/time;

// =============================================================================
// USER TYPES
// =============================================================================

public type User record {|
    string id;
    string email;
    string password_hash;
    string name;
    boolean email_verified = false;
    string? verification_token = ();
    time:Utc created_at;
    time:Utc updated_at;
    time:Utc? last_login = ();
    boolean is_active = true;
|};

public type UserRegistration record {|
    string email;
    string password;
    string name;
|};

public type UserLogin record {|
    string email;
    string password;
|};

public type UserProfile record {|
    string id;
    string email;
    string name;
    boolean email_verified;
    time:Utc created_at;
    time:Utc? last_login;
    BreachScanLog[] breachHistory?;
|};

// =============================================================================
// ADMIN TYPES
// =============================================================================

public type Admin record {|
    string id;
    string user_id;
    AdminRole role = "admin";
    json? permissions = ();
    time:Utc created_at;
    string? created_by = ();
|};

public enum AdminRole {
    admin = "admin",
    super_admin = "super_admin",
    cert_viewer = "cert_viewer"
}

// =============================================================================
// BREACH SCAN TYPES
// =============================================================================

public type BreachScanLog record {|
    string id;
    string user_id;
    string email;
    ScanType scan_type;
    json? breaches_found = ();
    ScanResult scan_result;
    json? hibp_response = ();
    time:Utc scanned_at;
    boolean notified = false;
|};

public enum ScanType {
    signup = "signup",
    email_change = "email_change",
    manual = "manual"
}

public enum ScanResult {
    clean = "clean",
    breached = "breached",
    error = "error"
}

public type HIBPBreach record {|
    string Name;
    string Title;
    string Domain;
    string BreachDate;
    string AddedDate;
    string ModifiedDate;
    int PwnCount;
    string Description;
    string[] DataClasses;
    boolean IsVerified;
    boolean IsFabricated;
    boolean IsSensitive;
    boolean IsRetired;
    boolean IsSpamList;
    string LogoPath;
|};

// =============================================================================
// THREAT REPORT TYPES
// =============================================================================

public type ThreatReport record {|
    string id;
    string title;
    string description;
    json? links = ();
    string? evidence = ();
    EvidenceType evidence_type = "text";
    string submitted_by;
    ThreatStatus status = "pending";
    Priority priority = "medium";
    ThreatCategory category = "other";
    time:Utc submitted_at;
    time:Utc updated_at;
    string? validated_by = ();
    time:Utc? validated_at = ();
    string? validation_remarks = ();
    boolean escalated_to_cert = false;
    time:Utc? escalated_at = ();
|};

public type ThreatReportSubmission record {|
    string title;
    string description;
    string[]? links = ();
    string? evidence = ();
    EvidenceType evidence_type = "text";
    ThreatCategory category = "other";
    Priority priority = "medium";
|};

public type ThreatReportUpdate record {|
    ThreatStatus status;
    string? validation_remarks = ();
    string validated_by;
|};

public enum ThreatStatus {
    pending = "pending",
    validated = "validated",
    false_alarm = "false_alarm",
    escalated = "escalated",
    needs_review = "needs_review"
}

public enum Priority {
    low = "low",
    medium = "medium",
    high = "high",
    critical = "critical"
}

public enum ThreatCategory {
    phishing = "phishing",
    malware = "malware",
    scam = "scam",
    data_breach = "data_breach",
    ddos = "ddos",
    other = "other"
}

public enum EvidenceType {
    image = "image",
    document = "document",
    text = "text"
}

// =============================================================================
// VIRUSTOTAL TYPES
// =============================================================================

public type VirusTotalScan record {|
    string id;
    string report_id;
    string url_or_hash;
    VirusTotalScanType scan_type;
    string? scan_id = ();
    int positives = 0;
    int total_engines = 0;
    time:Utc scan_date;
    json? result_details = ();
    VirusTotalVerdict verdict = "clean";
    string? permalink = ();
|};

public enum VirusTotalScanType {
    url = "url",
    file_hash = "file_hash",
    ip = "ip"
}

public enum VirusTotalVerdict {
    clean = "clean",
    suspicious = "suspicious",
    malicious = "malicious",
    error = "error"
}

public type VirusTotalResponse record {|
    json data;
    json? meta = ();
|};

// =============================================================================
// NOTIFICATION TYPES
// =============================================================================

public type Notification record {|
    string id;
    string user_id;
    NotificationType 'type;
    string title;
    string message;
    EntityType? related_entity_type = ();
    string? related_entity_id = ();
    NotificationStatus status = "unread";
    Priority priority = "normal";
    time:Utc created_at;
    time:Utc? read_at = ();
    boolean email_sent = false;
    time:Utc? email_sent_at = ();
|};

public type NotificationCreate record {|
    string user_id;
    NotificationType 'type;
    string title;
    string message;
    EntityType? related_entity_type = ();
    string? related_entity_id = ();
    Priority priority = "normal";
|};

public enum NotificationType {
    breach_detected = "breach_detected",
    report_update = "report_update",
    validation_complete = "validation_complete",
    system_alert = "system_alert"
}

public enum NotificationStatus {
    unread = "unread",
    read = "read",
    archived = "archived"
}

public enum EntityType {
    breach_scan = "breach_scan",
    threat_report = "threat_report",
    system = "system"
}

// =============================================================================
// CERT EXPORT TYPES
// =============================================================================

public type CERTExport record {|
    string id;
    string report_id;
    ExportFormat export_format;
    json? export_data = ();
    string exported_by;
    time:Utc exported_at;
    string? cert_response = ();
    DeliveryStatus delivery_status = "pending";
    DeliveryMethod delivery_method;
|};

public type CERTExportData record {|
    string reportId;
    string title;
    string description;
    string[] maliciousLinks;
    json? scanEvidence = ();
    string exportedBy;
    time:Utc exportedAt;
|};

public enum ExportFormat {
    json = "json",
    pdf = "pdf",
    xml = "xml"
}

public enum DeliveryStatus {
    pending = "pending",
    sent = "sent",
    delivered = "delivered",
    failed = "failed"
}

public enum DeliveryMethod {
    email = "email",
    api = "api",
    download = "download"
}

// =============================================================================
// API LOG TYPES
// =============================================================================

public type APILog record {|
    string id;
    ServiceName service_name;
    string endpoint;
    json? request_data = ();
    json? response_data = ();
    int? status_code = ();
    int? response_time_ms = ();
    string? error_message = ();
    time:Utc created_at;
    string? user_id = ();
|};

public enum ServiceName {
    hibp = "hibp",
    virustotal = "virustotal",
    cert = "cert"
}

// =============================================================================
// SYSTEM SETTINGS TYPES
// =============================================================================

public type SystemSetting record {|
    string id;
    string setting_key;
    string setting_value;
    string? description = ();
    string? updated_by = ();
    time:Utc updated_at;
|};

// =============================================================================
// JWT AND AUTH TYPES
// =============================================================================

public type JWTPayload record {|
    string sub; // user ID
    string email;
    string name;
    AdminRole? role = ();
    string iss; // issuer
    string aud; // audience
    int exp; // expiration time
    int iat; // issued at
|};

public type AuthResponse record {|
    string token;
    UserProfile user;
    string message;
|};

// =============================================================================
// API RESPONSE TYPES
// =============================================================================

public type APIResponse record {|
    boolean success;
    string message;
    json? data = ();
    string? errorCode = ();
|};

public type PaginatedResponse record {|
    boolean success;
    string message;
    json data;
    int total;
    int page;
    int per_page;
    int total_pages;
|};

// =============================================================================
// EMAIL TYPES
// =============================================================================

public type EmailData record {|
    string to;
    string subject;
    string body;
    string? from = ();
    boolean isHTML = false;
|};

public type EmailTemplate record {|
    string template_name;
    json template_data;
|};

// =============================================================================
// ERROR TYPES
// =============================================================================

public type CyberCareError record {|
    string code;
    string message;
    string? details = ();
    int httpStatusCode = 500;
|};
# CyberCare API Documentation

## Overview

CyberCare is a community-powered cyber threat monitoring system that allows users to report cyber threats while protecting their privacy. The system integrates with HaveIBeenPwned for breach detection and VirusTotal for threat validation.

**Base URL:** `http://localhost:8080/api`

## Authentication

The API uses JWT (JSON Web Tokens) for authentication. Include the token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

## API Endpoints

### System Health & Information

#### Get API Documentation
```http
GET /docs
```

**Response:**
```json
{
  "service": "CyberCare API",
  "version": "1.0.0",
  "description": "Community-Powered Cyber Threat Monitoring System",
  "endpoints": { ... },
  "authentication": { ... }
}
```

#### Basic Health Check
```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "CyberCare Backend",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Comprehensive System Health
```http
GET /health/system
```

**Response:**
```json
{
  "status": "healthy",
  "services": {
    "database": { "status": "healthy" },
    "hibp": { "status": "healthy" },
    "virustotal": { "status": "healthy" },
    "email": { "status": "healthy" }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### User Management

#### User Registration
```http
POST /users/signup
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123",
  "name": "John Doe"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Account created successfully. Please check your email for verification.",
  "data": {
    "userId": "user-uuid",
    "email": "user@example.com",
    "emailVerified": false
  }
}
```

#### User Login
```http
POST /users/login
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "token": "jwt-token-here",
    "user": {
      "id": "user-uuid",
      "email": "user@example.com",
      "name": "John Doe",
      "emailVerified": true,
      "createdAt": "2024-01-15T10:30:00Z",
      "lastLogin": "2024-01-15T12:00:00Z"
    },
    "message": "Login successful"
  }
}
```

#### Get User Profile
```http
GET /users/me
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "user-uuid",
    "email": "user@example.com",
    "name": "John Doe",
    "emailVerified": true,
    "createdAt": "2024-01-15T10:30:00Z",
    "lastLogin": "2024-01-15T12:00:00Z",
    "breachHistory": [
      {
        "id": "scan-uuid",
        "email": "user@example.com",
        "scanType": "signup",
        "scanResult": "breached",
        "breachesFound": ["Adobe", "LinkedIn"],
        "scannedAt": "2024-01-15T10:30:00Z"
      }
    ]
  }
}
```

#### Verify Email
```http
POST /users/verify-email
```

**Request Body:**
```json
{
  "token": "verification-token"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Email verified successfully! Welcome to CyberCare."
}
```

#### Rescan Email for Breaches
```http
POST /users/rescan-breaches
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "message": "Email scan completed",
  "data": {
    "scanResult": "breached",
    "breachesFound": ["Adobe", "LinkedIn"],
    "scannedAt": "2024-01-15T12:00:00Z"
  }
}
```

### Threat Reporting

#### Submit Threat Report
```http
POST /threats/reports
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "title": "Phishing Site Targeting Bank Customers",
  "description": "Found a fake banking website trying to steal credentials",
  "links": ["http://fake-bank-site.com"],
  "evidence": "base64-encoded-screenshot",
  "evidenceType": "image",
  "category": "phishing",
  "priority": "high"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Threat report submitted successfully",
  "data": {
    "reportId": "report-uuid",
    "status": "pending",
    "submittedAt": "2024-01-15T12:00:00Z"
  }
}
```

#### Get User's Threat Reports
```http
GET /threats/reports?page=1&limit=10
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "report-uuid",
      "title": "Phishing Site Targeting Bank Customers",
      "description": "Found a fake banking website...",
      "status": "validated",
      "priority": "high",
      "category": "phishing",
      "submittedAt": "2024-01-15T12:00:00Z",
      "updatedAt": "2024-01-15T14:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 25,
    "totalPages": 3
  }
}
```

#### Get Specific Threat Report
```http
GET /threats/reports/{reportId}
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "report": {
      "id": "report-uuid",
      "title": "Phishing Site Targeting Bank Customers",
      "description": "Found a fake banking website...",
      "links": ["http://fake-bank-site.com"],
      "status": "validated",
      "priority": "high",
      "category": "phishing",
      "submittedAt": "2024-01-15T12:00:00Z",
      "validatedBy": "admin-uuid",
      "validatedAt": "2024-01-15T14:00:00Z",
      "validationRemarks": "Confirmed malicious by VirusTotal scan"
    },
    "virusTotalScans": [
      {
        "id": "scan-uuid",
        "urlOrHash": "http://fake-bank-site.com",
        "positives": 8,
        "totalEngines": 70,
        "verdict": "malicious",
        "scanDate": "2024-01-15T12:05:00Z"
      }
    ],
    "scanSummary": {
      "totalScans": 1,
      "malicious": 1,
      "suspicious": 0,
      "clean": 0,
      "overallThreatLevel": "validated"
    }
  }
}
```

#### Get Threat Statistics
```http
GET /threats/stats
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "totalReports": 150,
    "pendingReports": 25,
    "validatedReports": 85,
    "falseAlarms": 30,
    "escalatedReports": 10,
    "phishingReports": 60,
    "malwareReports": 40,
    "scamReports": 30
  }
}
```

### Admin Functions

#### Get All Threat Reports (Admin)
```http
GET /threats/admin/reports?status=pending&category=phishing&page=1&limit=20
Authorization: Bearer <admin-token>
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "report-uuid",
      "title": "Suspicious Email Link",
      "status": "pending",
      "priority": "medium",
      "category": "phishing",
      "submittedBy": "user-uuid",
      "submittedAt": "2024-01-15T12:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 45,
    "totalPages": 3
  }
}
```

#### Update Threat Report Status (Admin)
```http
PUT /threats/reports/{reportId}/status
Authorization: Bearer <admin-token>
```

**Request Body:**
```json
{
  "status": "validated",
  "validationRemarks": "Confirmed malicious through VirusTotal analysis",
  "validatedBy": "admin-uuid"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Threat report status updated successfully"
}
```

## Error Responses

All endpoints return errors in the following format:

```json
{
  "success": false,
  "message": "Error description",
  "errorCode": "ERROR_CODE"
}
```

### Common HTTP Status Codes

- **200 OK**: Request successful
- **201 Created**: Resource created successfully
- **400 Bad Request**: Invalid request data
- **401 Unauthorized**: Authentication required or invalid
- **403 Forbidden**: Access denied (insufficient permissions)
- **404 Not Found**: Resource not found
- **409 Conflict**: Resource already exists
- **500 Internal Server Error**: Server error

## Data Types

### User Object
```json
{
  "id": "string (UUID)",
  "email": "string",
  "name": "string",
  "emailVerified": "boolean",
  "createdAt": "string (ISO 8601)",
  "lastLogin": "string (ISO 8601) | null"
}
```

### Threat Report Object
```json
{
  "id": "string (UUID)",
  "title": "string",
  "description": "string",
  "links": "string[] | null",
  "evidence": "string | null",
  "evidenceType": "image | document | text",
  "submittedBy": "string (UUID)",
  "status": "pending | validated | false_alarm | escalated | needs_review",
  "priority": "low | medium | high | critical",
  "category": "phishing | malware | scam | data_breach | ddos | other",
  "submittedAt": "string (ISO 8601)",
  "updatedAt": "string (ISO 8601)",
  "validatedBy": "string (UUID) | null",
  "validatedAt": "string (ISO 8601) | null",
  "validationRemarks": "string | null"
}
```

### Breach Scan Log Object
```json
{
  "id": "string (UUID)",
  "email": "string",
  "scanType": "signup | email_change | manual",
  "scanResult": "clean | breached | error",
  "breachesFound": "string[] | null",
  "scannedAt": "string (ISO 8601)",
  "notified": "boolean"
}
```

### VirusTotal Scan Object
```json
{
  "id": "string (UUID)",
  "urlOrHash": "string",
  "positives": "number",
  "totalEngines": "number",
  "verdict": "clean | suspicious | malicious | error",
  "scanDate": "string (ISO 8601)",
  "permalink": "string | null"
}
```

## Rate Limiting

- **Authentication endpoints**: 5 requests per minute per IP
- **Threat reporting**: 10 reports per hour per user
- **General API**: 100 requests per minute per user
- **Admin endpoints**: 200 requests per minute per admin

## Webhooks

CyberCare can send webhooks for important events:

### Webhook Events
- `threat.validated`: When a threat is validated
- `threat.escalated`: When a threat is escalated to CERT
- `breach.detected`: When a new breach is detected for a user

### Webhook Payload
```json
{
  "event": "threat.validated",
  "timestamp": "2024-01-15T12:00:00Z",
  "data": {
    "reportId": "report-uuid",
    "title": "Phishing Site",
    "status": "validated",
    "submittedBy": "user-uuid"
  }
}
```

## SDK Examples

### JavaScript/Node.js
```javascript
const cybercare = new CyberCareAPI('http://localhost:8080/api');

// Login
const auth = await cybercare.auth.login('user@example.com', 'password');
cybercare.setToken(auth.token);

// Submit threat report
const report = await cybercare.threats.submit({
  title: 'Suspicious Email',
  description: 'Received phishing email',
  category: 'phishing',
  priority: 'medium'
});

// Get user profile
const profile = await cybercare.users.getProfile();
```

### Python
```python
from cybercare import CyberCareAPI

client = CyberCareAPI('http://localhost:8080/api')

# Login
auth = client.auth.login('user@example.com', 'password')
client.set_token(auth['token'])

# Submit threat report
report = client.threats.submit({
    'title': 'Suspicious Email',
    'description': 'Received phishing email',
    'category': 'phishing',
    'priority': 'medium'
})

# Get threat statistics
stats = client.threats.get_statistics()
```

## Support

For API support and questions:
- **Documentation**: [API Docs](http://localhost:8080/api/docs)
- **Health Check**: [System Status](http://localhost:8080/api/health/system)
- **GitHub**: [CyberCare Repository](https://github.com/cybercare/backend)

## Changelog

### v1.0.0 (2024-01-15)
- Initial API release
- User authentication and management
- Threat reporting system
- HaveIBeenPwned integration
- VirusTotal integration
- Email notifications
- Admin panel functionality
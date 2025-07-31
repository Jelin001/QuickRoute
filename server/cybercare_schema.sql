-- CyberCare Database Schema
-- Created for CyberCare Community-Powered Cyber Threat Monitoring System

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- Create Database
CREATE DATABASE IF NOT EXISTS cybercare_db;
USE cybercare_db;

-- ----------------------------
-- Table structure for users
-- ----------------------------
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` varchar(36) NOT NULL,
  `email` varchar(255) NOT NULL UNIQUE,
  `password_hash` varchar(255) NOT NULL,
  `name` varchar(100) NOT NULL,
  `email_verified` boolean DEFAULT FALSE,
  `verification_token` varchar(255) DEFAULT NULL,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `last_login` timestamp NULL,
  `is_active` boolean DEFAULT TRUE,
  PRIMARY KEY (`id`),
  INDEX `idx_email` (`email`),
  INDEX `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table structure for admins
-- ----------------------------
DROP TABLE IF EXISTS `admins`;
CREATE TABLE `admins` (
  `id` varchar(36) NOT NULL,
  `user_id` varchar(36) NOT NULL,
  `role` enum('admin', 'super_admin', 'cert_viewer') DEFAULT 'admin',
  `permissions` json DEFAULT NULL,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  `created_by` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`created_by`) REFERENCES `users`(`id`) ON DELETE SET NULL,
  INDEX `idx_user_id` (`user_id`),
  INDEX `idx_role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table structure for breach_scan_logs
-- ----------------------------
DROP TABLE IF EXISTS `breach_scan_logs`;
CREATE TABLE `breach_scan_logs` (
  `id` varchar(36) NOT NULL,
  `user_id` varchar(36) NOT NULL,
  `email` varchar(255) NOT NULL,
  `scan_type` enum('signup', 'email_change', 'manual') NOT NULL,
  `breaches_found` json DEFAULT NULL,
  `scan_result` enum('clean', 'breached', 'error') NOT NULL,
  `hibp_response` json DEFAULT NULL,
  `scanned_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  `notified` boolean DEFAULT FALSE,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  INDEX `idx_user_id` (`user_id`),
  INDEX `idx_email` (`email`),
  INDEX `idx_scan_type` (`scan_type`),
  INDEX `idx_scanned_at` (`scanned_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table structure for threat_reports
-- ----------------------------
DROP TABLE IF EXISTS `threat_reports`;
CREATE TABLE `threat_reports` (
  `id` varchar(36) NOT NULL,
  `title` varchar(255) NOT NULL,
  `description` text NOT NULL,
  `links` json DEFAULT NULL,
  `evidence` longtext DEFAULT NULL,
  `evidence_type` enum('image', 'document', 'text') DEFAULT 'text',
  `submitted_by` varchar(36) NOT NULL,
  `status` enum('pending', 'validated', 'false_alarm', 'escalated', 'needs_review') DEFAULT 'pending',
  `priority` enum('low', 'medium', 'high', 'critical') DEFAULT 'medium',
  `category` enum('phishing', 'malware', 'scam', 'data_breach', 'ddos', 'other') DEFAULT 'other',
  `submitted_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `validated_by` varchar(36) DEFAULT NULL,
  `validated_at` timestamp NULL,
  `validation_remarks` text DEFAULT NULL,
  `escalated_to_cert` boolean DEFAULT FALSE,
  `escalated_at` timestamp NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`submitted_by`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`validated_by`) REFERENCES `users`(`id`) ON DELETE SET NULL,
  INDEX `idx_submitted_by` (`submitted_by`),
  INDEX `idx_status` (`status`),
  INDEX `idx_priority` (`priority`),
  INDEX `idx_category` (`category`),
  INDEX `idx_submitted_at` (`submitted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table structure for virustotal_scans
-- ----------------------------
DROP TABLE IF EXISTS `virustotal_scans`;
CREATE TABLE `virustotal_scans` (
  `id` varchar(36) NOT NULL,
  `report_id` varchar(36) NOT NULL,
  `url_or_hash` varchar(500) NOT NULL,
  `scan_type` enum('url', 'file_hash', 'ip') NOT NULL,
  `scan_id` varchar(255) DEFAULT NULL,
  `positives` int DEFAULT 0,
  `total_engines` int DEFAULT 0,
  `scan_date` timestamp DEFAULT CURRENT_TIMESTAMP,
  `result_details` json DEFAULT NULL,
  `verdict` enum('clean', 'suspicious', 'malicious', 'error') DEFAULT 'clean',
  `permalink` varchar(500) DEFAULT NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`report_id`) REFERENCES `threat_reports`(`id`) ON DELETE CASCADE,
  INDEX `idx_report_id` (`report_id`),
  INDEX `idx_verdict` (`verdict`),
  INDEX `idx_scan_date` (`scan_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table structure for notifications
-- ----------------------------
DROP TABLE IF EXISTS `notifications`;
CREATE TABLE `notifications` (
  `id` varchar(36) NOT NULL,
  `user_id` varchar(36) NOT NULL,
  `type` enum('breach_detected', 'report_update', 'validation_complete', 'system_alert') NOT NULL,
  `title` varchar(255) NOT NULL,
  `message` text NOT NULL,
  `related_entity_type` enum('breach_scan', 'threat_report', 'system') DEFAULT NULL,
  `related_entity_id` varchar(36) DEFAULT NULL,
  `status` enum('unread', 'read', 'archived') DEFAULT 'unread',
  `priority` enum('low', 'normal', 'high') DEFAULT 'normal',
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  `read_at` timestamp NULL,
  `email_sent` boolean DEFAULT FALSE,
  `email_sent_at` timestamp NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  INDEX `idx_user_id` (`user_id`),
  INDEX `idx_type` (`type`),
  INDEX `idx_status` (`status`),
  INDEX `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table structure for cert_exports
-- ----------------------------
DROP TABLE IF EXISTS `cert_exports`;
CREATE TABLE `cert_exports` (
  `id` varchar(36) NOT NULL,
  `report_id` varchar(36) NOT NULL,
  `export_format` enum('json', 'pdf', 'xml') NOT NULL,
  `export_data` json DEFAULT NULL,
  `exported_by` varchar(36) NOT NULL,
  `exported_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  `cert_response` text DEFAULT NULL,
  `delivery_status` enum('pending', 'sent', 'delivered', 'failed') DEFAULT 'pending',
  `delivery_method` enum('email', 'api', 'download') NOT NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`report_id`) REFERENCES `threat_reports`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`exported_by`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  INDEX `idx_report_id` (`report_id`),
  INDEX `idx_exported_by` (`exported_by`),
  INDEX `idx_delivery_status` (`delivery_status`),
  INDEX `idx_exported_at` (`exported_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table structure for api_logs
-- ----------------------------
DROP TABLE IF EXISTS `api_logs`;
CREATE TABLE `api_logs` (
  `id` varchar(36) NOT NULL,
  `service_name` enum('hibp', 'virustotal', 'cert') NOT NULL,
  `endpoint` varchar(255) NOT NULL,
  `request_data` json DEFAULT NULL,
  `response_data` json DEFAULT NULL,
  `status_code` int DEFAULT NULL,
  `response_time_ms` int DEFAULT NULL,
  `error_message` text DEFAULT NULL,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  `user_id` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL,
  INDEX `idx_service_name` (`service_name`),
  INDEX `idx_created_at` (`created_at`),
  INDEX `idx_status_code` (`status_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table structure for system_settings
-- ----------------------------
DROP TABLE IF EXISTS `system_settings`;
CREATE TABLE `system_settings` (
  `id` varchar(36) NOT NULL,
  `setting_key` varchar(100) NOT NULL UNIQUE,
  `setting_value` text NOT NULL,
  `description` text DEFAULT NULL,
  `updated_by` varchar(36) DEFAULT NULL,
  `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`updated_by`) REFERENCES `users`(`id`) ON DELETE SET NULL,
  INDEX `idx_setting_key` (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Insert default system settings
-- ----------------------------
INSERT INTO `system_settings` (`id`, `setting_key`, `setting_value`, `description`) VALUES
(UUID(), 'auto_scan_on_signup', 'true', 'Automatically scan email for breaches on user signup'),
(UUID(), 'virustotal_auto_scan', 'true', 'Automatically scan URLs through VirusTotal'),
(UUID(), 'cert_auto_export', 'false', 'Automatically export validated threats to CERT'),
(UUID(), 'email_notifications', 'true', 'Send email notifications to users'),
(UUID(), 'breach_notification_threshold', '1', 'Minimum number of breaches to trigger notification'),
(UUID(), 'virustotal_positive_threshold', '3', 'Minimum positive detections to mark as malicious');

-- ----------------------------
-- Create default admin user (optional - for testing)
-- ----------------------------
-- Password: 'admin123' (hashed - you should change this in production)
INSERT INTO `users` (`id`, `email`, `password_hash`, `name`, `email_verified`, `is_active`) VALUES
('admin-001', 'admin@cybercare.com', '$2b$10$8K1p/a4mYCUQaHq7rjKKe.WNV/gYPW6zt7QwJyh5Xvt5r4ZtKrL6C', 'System Administrator', TRUE, TRUE);

INSERT INTO `admins` (`id`, `user_id`, `role`, `created_at`) VALUES
('admin-role-001', 'admin-001', 'super_admin', CURRENT_TIMESTAMP);

SET FOREIGN_KEY_CHECKS = 1;
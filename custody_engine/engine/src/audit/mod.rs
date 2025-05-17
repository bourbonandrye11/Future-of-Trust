

use std::collections::VecDeque;
use std::sync::Mutex;

/// Type of custody event being tracked
#[derive(Debug, Clone)]
pub enum AuditEventType {
    Keygen,
    Signing,
    Aggregation,
    Verification,
    Error,
}

/// Record of a custody-related event
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub event_type: AuditEventType,
    pub session_id: String,
    pub participant_id: Option<u8>,
    pub message: String,
    pub timestamp: String, // RFC3339 string (can upgrade later)
}

/// In-memory audit tracker
pub struct AuditTracker {
    pub records: Mutex<VecDeque<AuditRecord>>, // could persist/log later
    pub max_entries: usize,
}

impl AuditTracker {
    pub fn new(max_entries: usize) -> Self {
        Self {
            records: Mutex::new(VecDeque::with_capacity(max_entries)),
            max_entries,
        }
    }

    /// Record a new event in the audit log
    pub fn log(&self, record: AuditRecord) {
        let mut records = self.records.lock().unwrap();
        if records.len() == self.max_entries {
            records.pop_front(); // evict oldest
        }
        records.push_back(record);
        println!("📋 AUDIT LOG [{}] {}{} :: {}", 
            record.event_type_label(), 
            record.session_id,
            record.participant_id.map_or(String::new(), |id| format!(" (P#{})", id)),
            record.message);
    }

    /// Optional: view recent logs
    pub fn recent(&self, count: usize) -> Vec<AuditRecord> {
        let records = self.records.lock().unwrap();
        records.iter().rev().take(count).cloned().collect()
    }
}

impl AuditRecord {
    pub fn event_type_label(&self) -> &'static str {
        match self.event_type {
            AuditEventType::Keygen => "KEYGEN",
            AuditEventType::Signing => "SIGNING",
            AuditEventType::Aggregation => "AGGREGATE",
            AuditEventType::Verification => "VERIFY",
            AuditEventType::Error => "ERROR",
        }
    }
}

/// Helper to get current timestamp as RFC3339 string
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Global audit tracker instance for quick drop-in use
use once_cell::sync::Lazy;
pub static AUDIT: Lazy<AuditTracker> = Lazy::new(|| AuditTracker::new(500));
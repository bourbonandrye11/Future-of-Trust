

use custody_engine::audit::{AuditRecord, AuditEventType, AuditTracker, now_rfc3339};

#[test]
fn test_audit_log_adds_and_retrieves() {
    let tracker = AuditTracker::new(10);

    tracker.log(AuditRecord {
        event_type: AuditEventType::Keygen,
        session_id: "session_1".into(),
        participant_id: None,
        message: "Generated keyset".into(),
        timestamp: now_rfc3339(),
    });

    let recent = tracker.recent(1);
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].session_id, "session_1");
    assert_eq!(recent[0].message, "Generated keyset");
}

#[test]
fn test_audit_log_eviction() {
    let tracker = AuditTracker::new(3);

    for i in 0..5 {
        tracker.log(AuditRecord {
            event_type: AuditEventType::Signing,
            session_id: format!("session_{}", i),
            participant_id: Some(i as u8),
            message: format!("Signed as P#{}", i),
            timestamp: now_rfc3339(),
        });
    }

    let recent = tracker.recent(5);
    assert_eq!(recent.len(), 3); // oldest two evicted
    assert_eq!(recent[0].session_id, "session_4");
    assert_eq!(recent[2].session_id, "session_2");
}

#[test]
fn test_audit_log_thread_safety() {
    use std::thread;

    let tracker = AuditTracker::new(100);

    let handles: Vec<_> = (0..10).map(|i| {
        let tracker = &tracker;
        thread::spawn(move || {
            tracker.log(AuditRecord {
                event_type: AuditEventType::Signing,
                session_id: format!("thread_{}", i),
                participant_id: Some(i as u8),
                message: format!("Thread sign event {}", i),
                timestamp: now_rfc3339(),
            });
        })
    }).collect();

    for h in handles {
        h.join().expect("Thread failed");
    }

    let recent = tracker.recent(10);
    assert_eq!(recent.len(), 10);
}
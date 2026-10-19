use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::plugins::artifact_plugin::{IngestCtx, IngestStats};

#[derive(Clone, Serialize)]
pub struct JobView {
    pub id: u64,
    pub evidence_id: i64,
    pub status: String,
    pub phase: String,
    pub processed: u64,
    pub total: u64,
    pub stats: Option<IngestStats>,
    pub error: Option<String>,
}

pub struct Job {
    pub id: u64,
    pub evidence_id: i64,
    pub ctx: Arc<IngestCtx>,
    pub outcome: Mutex<Outcome>,
}

pub enum Outcome {
    Running,
    Done(IngestStats),
    Cancelled(IngestStats),
    Error(String),
}

impl Job {
    pub fn view(&self) -> JobView {
        let outcome = self.outcome.lock().unwrap();
        let (status, stats, error) = match &*outcome {
            Outcome::Running => ("running", None, None),
            Outcome::Done(s) => ("done", Some(*s), None),
            Outcome::Cancelled(s) => ("cancelled", Some(*s), None),
            Outcome::Error(e) => ("error", None, Some(e.clone())),
        };
        let phase = self.ctx.phase.lock().map(|p| p.clone()).unwrap_or_default();
        JobView {
            id: self.id,
            evidence_id: self.evidence_id,
            status: status.to_string(),
            phase,
            processed: self.ctx.processed.load(Ordering::Relaxed),
            total: self.ctx.total_estimate.load(Ordering::Relaxed),
            stats,
            error,
        }
    }
}

pub struct JobRegistry {
    next_id: AtomicU64,
    jobs: Mutex<HashMap<u64, Arc<Job>>>,
}

impl JobRegistry {
    pub fn new() -> JobRegistry {
        JobRegistry {
            next_id: AtomicU64::new(1),
            jobs: Mutex::new(HashMap::new()),
        }
    }

    pub fn create(&self, evidence_id: i64, total_estimate: u64) -> Arc<Job> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let job = Arc::new(Job {
            id,
            evidence_id,
            ctx: Arc::new(IngestCtx::new(total_estimate)),
            outcome: Mutex::new(Outcome::Running),
        });
        self.jobs.lock().unwrap().insert(id, job.clone());
        job
    }

    pub fn get(&self, id: u64) -> Option<Arc<Job>> {
        self.jobs.lock().unwrap().get(&id).cloned()
    }

    pub fn finish(&self, id: u64, outcome: Outcome) {
        if let Some(job) = self.get(id) {
            *job.outcome.lock().unwrap() = outcome;
        }
    }
}

impl Default for JobRegistry {
    fn default() -> Self {
        JobRegistry::new()
    }
}

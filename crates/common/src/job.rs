//! Background job management for long-running tasks
//!
//! Provides infrastructure for executing tasks asynchronously in background threads
//! without blocking the main beacon checkin loop.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use crate::{KrakenError, TaskId};

pub type JobId = u32;

/// Job execution status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum JobStatus {
    Running = 0,
    Completed = 1,
    Failed = 2,
    Cancelled = 3,
}

impl From<u8> for JobStatus {
    fn from(val: u8) -> Self {
        match val {
            0 => JobStatus::Running,
            1 => JobStatus::Completed,
            2 => JobStatus::Failed,
            3 => JobStatus::Cancelled,
            _ => JobStatus::Running, // Default to running for unknown values
        }
    }
}

impl From<JobStatus> for u8 {
    fn from(status: JobStatus) -> Self {
        status as u8
    }
}

/// A background job
pub struct Job {
    pub id: JobId,
    pub task_id: TaskId,
    pub description: String,
    pub status: Arc<AtomicU8>,
    pub created_at: SystemTime,
    pub completed_at: Mutex<Option<SystemTime>>,
    pub output: Arc<Mutex<Vec<u8>>>,
    pub error: Arc<Mutex<Option<String>>>,
    pub cancel_flag: Arc<AtomicBool>,
    pub progress: Arc<AtomicU32>, // 0-100 percentage
}

impl Job {
    /// Create a new job
    pub fn new(id: JobId, task_id: TaskId, description: String) -> Self {
        Self {
            id,
            task_id,
            description,
            status: Arc::new(AtomicU8::new(JobStatus::Running as u8)),
            created_at: SystemTime::now(),
            completed_at: Mutex::new(None),
            output: Arc::new(Mutex::new(Vec::new())),
            error: Arc::new(Mutex::new(None)),
            cancel_flag: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Get current job status
    pub fn get_status(&self) -> JobStatus {
        JobStatus::from(self.status.load(Ordering::SeqCst))
    }

    /// Set job status
    pub fn set_status(&self, status: JobStatus) {
        self.status.store(status as u8, Ordering::SeqCst);
        if status != JobStatus::Running {
            *self.completed_at.lock().unwrap() = Some(SystemTime::now());
        }
    }

    /// Check if job should be cancelled
    pub fn should_cancel(&self) -> bool {
        self.cancel_flag.load(Ordering::SeqCst)
    }

    /// Request job cancellation
    pub fn request_cancel(&self) {
        self.cancel_flag.store(true, Ordering::SeqCst);
    }

    /// Get current progress (0-100)
    pub fn get_progress(&self) -> u32 {
        self.progress.load(Ordering::SeqCst).min(100)
    }

    /// Set progress (0-100)
    pub fn set_progress(&self, progress: u32) {
        self.progress.store(progress.min(100), Ordering::SeqCst);
    }

    /// Append output data
    pub fn append_output(&self, data: &[u8]) {
        self.output.lock().unwrap().extend_from_slice(data);
    }

    /// Set error message
    pub fn set_error(&self, error: String) {
        *self.error.lock().unwrap() = Some(error);
        self.set_status(JobStatus::Failed);
    }

    /// Mark job as completed
    pub fn complete(&self) {
        self.set_status(JobStatus::Completed);
        self.set_progress(100);
    }

    /// Get elapsed time in seconds
    pub fn elapsed_secs(&self) -> u64 {
        self.created_at
            .elapsed()
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Job output for transmission to server
#[derive(Debug, Clone)]
pub struct JobOutput {
    pub job_id: JobId,
    pub task_id: TaskId,
    pub output: Vec<u8>,
    pub is_final: bool,
    pub final_status: Option<JobStatus>,
}

/// Job manager coordinates background task execution
pub struct JobManager {
    jobs: Arc<RwLock<HashMap<JobId, Arc<Job>>>>,
    next_id: Arc<AtomicU32>,
    output_queue: Arc<Mutex<VecDeque<JobOutput>>>,
    max_concurrent: usize,
}

impl JobManager {
    /// Create a new job manager
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(AtomicU32::new(1)),
            output_queue: Arc::new(Mutex::new(VecDeque::new())),
            max_concurrent,
        }
    }

    /// Create a new job and return its ID
    pub fn create_job(&self, task_id: TaskId, description: String) -> Result<JobId, KrakenError> {
        // Check concurrent job limit
        let active_count = self
            .jobs
            .read()
            .unwrap()
            .values()
            .filter(|j| j.get_status() == JobStatus::Running)
            .count();

        if active_count >= self.max_concurrent {
            return Err(KrakenError::Module(format!(
                "maximum concurrent jobs ({}) reached",
                self.max_concurrent
            )));
        }

        let job_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let job = Arc::new(Job::new(job_id, task_id, description));

        self.jobs.write().unwrap().insert(job_id, job);

        Ok(job_id)
    }

    /// Get a job by ID
    pub fn get_job(&self, job_id: JobId) -> Option<Arc<Job>> {
        self.jobs.read().unwrap().get(&job_id).cloned()
    }

    /// List all jobs
    pub fn list_jobs(&self) -> Vec<Arc<Job>> {
        self.jobs.read().unwrap().values().cloned().collect()
    }

    /// List active (running) jobs
    pub fn list_active_jobs(&self) -> Vec<Arc<Job>> {
        self.jobs
            .read()
            .unwrap()
            .values()
            .filter(|j| j.get_status() == JobStatus::Running)
            .cloned()
            .collect()
    }

    /// Cancel a job
    pub fn cancel_job(&self, job_id: JobId) -> Result<(), KrakenError> {
        let job = self
            .get_job(job_id)
            .ok_or_else(|| KrakenError::NotFound(format!("job {} not found", job_id)))?;

        job.request_cancel();
        job.set_status(JobStatus::Cancelled);

        Ok(())
    }

    /// Cancel all running jobs
    pub fn cancel_all(&self) {
        for job in self.list_active_jobs() {
            job.request_cancel();
            job.set_status(JobStatus::Cancelled);
        }
    }

    /// Queue job output for transmission
    pub fn queue_output(&self, output: JobOutput) {
        self.output_queue.lock().unwrap().push_back(output);
    }

    /// Dequeue job outputs (for sending to server)
    pub fn dequeue_outputs(&self, max_count: usize) -> Vec<JobOutput> {
        let mut queue = self.output_queue.lock().unwrap();
        let count = max_count.min(queue.len());
        queue.drain(..count).collect()
    }

    /// Check if output queue has pending outputs
    pub fn has_pending_output(&self) -> bool {
        !self.output_queue.lock().unwrap().is_empty()
    }

    /// Clean up completed jobs older than the specified duration
    pub fn cleanup_old_jobs(&self, max_age_secs: u64) {
        let now = SystemTime::now();
        let mut jobs = self.jobs.write().unwrap();

        jobs.retain(|_, job| {
            let status = job.get_status();
            if status == JobStatus::Running {
                return true; // Keep running jobs
            }

            // Check age of completed jobs
            if let Ok(Some(completed_at)) = job.completed_at.lock().map(|lock| *lock) {
                if let Ok(elapsed) = now.duration_since(completed_at) {
                    return elapsed.as_secs() < max_age_secs;
                }
            }

            true // Keep if we can't determine age
        });
    }

    /// Get job count by status
    pub fn count_by_status(&self, status: JobStatus) -> usize {
        self.jobs
            .read()
            .unwrap()
            .values()
            .filter(|j| j.get_status() == status)
            .count()
    }

    /// Get total job count
    pub fn total_jobs(&self) -> usize {
        self.jobs.read().unwrap().len()
    }
}

impl Default for JobManager {
    fn default() -> Self {
        Self::new(10) // Default: max 10 concurrent jobs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_creation() {
        let task_id = TaskId::new();
        let job = Job::new(1, task_id, "test job".to_string());

        assert_eq!(job.id, 1);
        assert_eq!(job.task_id, task_id);
        assert_eq!(job.description, "test job");
        assert_eq!(job.get_status(), JobStatus::Running);
        assert_eq!(job.get_progress(), 0);
        assert!(!job.should_cancel());
    }

    #[test]
    fn test_job_status_transitions() {
        let job = Job::new(1, TaskId::new(), "test".to_string());

        assert_eq!(job.get_status(), JobStatus::Running);

        job.set_status(JobStatus::Completed);
        assert_eq!(job.get_status(), JobStatus::Completed);

        assert!(job.completed_at.lock().unwrap().is_some());
    }

    #[test]
    fn test_job_progress() {
        let job = Job::new(1, TaskId::new(), "test".to_string());

        job.set_progress(50);
        assert_eq!(job.get_progress(), 50);

        job.set_progress(150); // Over 100
        assert_eq!(job.get_progress(), 100); // Should cap at 100
    }

    #[test]
    fn test_job_cancellation() {
        let job = Job::new(1, TaskId::new(), "test".to_string());

        assert!(!job.should_cancel());

        job.request_cancel();
        assert!(job.should_cancel());
    }

    #[test]
    fn test_job_output() {
        let job = Job::new(1, TaskId::new(), "test".to_string());

        job.append_output(b"hello ");
        job.append_output(b"world");

        let output = job.output.lock().unwrap();
        assert_eq!(&*output, b"hello world");
    }

    #[test]
    fn test_job_manager_creation() {
        let manager = JobManager::new(5);
        let task_id = TaskId::new();

        let job_id = manager.create_job(task_id, "test".to_string()).unwrap();
        assert_eq!(job_id, 1);

        let job = manager.get_job(job_id).unwrap();
        assert_eq!(job.description, "test");
    }

    #[test]
    fn test_job_manager_concurrent_limit() {
        let manager = JobManager::new(2); // Max 2 concurrent

        let job1 = manager.create_job(TaskId::new(), "job1".to_string()).unwrap();
        let job2 = manager.create_job(TaskId::new(), "job2".to_string()).unwrap();

        // Third job should fail
        let result = manager.create_job(TaskId::new(), "job3".to_string());
        assert!(result.is_err());

        // Complete one job
        manager.get_job(job1).unwrap().complete();

        // Now third job should succeed
        let job3 = manager.create_job(TaskId::new(), "job3".to_string()).unwrap();
        assert_eq!(job3, 3);
    }

    #[test]
    fn test_job_manager_list() {
        let manager = JobManager::new(10);

        manager.create_job(TaskId::new(), "job1".to_string()).unwrap();
        manager.create_job(TaskId::new(), "job2".to_string()).unwrap();

        let jobs = manager.list_jobs();
        assert_eq!(jobs.len(), 2);

        let active = manager.list_active_jobs();
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn test_job_manager_cancel() {
        let manager = JobManager::new(10);
        let job_id = manager.create_job(TaskId::new(), "test".to_string()).unwrap();

        manager.cancel_job(job_id).unwrap();

        let job = manager.get_job(job_id).unwrap();
        assert_eq!(job.get_status(), JobStatus::Cancelled);
        assert!(job.should_cancel());
    }

    #[test]
    fn test_job_manager_cancel_all() {
        let manager = JobManager::new(10);

        manager.create_job(TaskId::new(), "job1".to_string()).unwrap();
        manager.create_job(TaskId::new(), "job2".to_string()).unwrap();

        manager.cancel_all();

        let active = manager.list_active_jobs();
        assert_eq!(active.len(), 0);
    }

    #[test]
    fn test_output_queue() {
        let manager = JobManager::new(10);

        let output1 = JobOutput {
            job_id: 1,
            task_id: TaskId::new(),
            output: b"output1".to_vec(),
            is_final: false,
            final_status: None,
        };

        let output2 = JobOutput {
            job_id: 2,
            task_id: TaskId::new(),
            output: b"output2".to_vec(),
            is_final: true,
            final_status: Some(JobStatus::Completed),
        };

        manager.queue_output(output1.clone());
        manager.queue_output(output2.clone());

        assert!(manager.has_pending_output());

        let outputs = manager.dequeue_outputs(10);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].job_id, 1);
        assert_eq!(outputs[1].job_id, 2);

        assert!(!manager.has_pending_output());
    }

    #[test]
    fn test_count_by_status() {
        let manager = JobManager::new(10);

        let job1 = manager.create_job(TaskId::new(), "job1".to_string()).unwrap();
        let job2 = manager.create_job(TaskId::new(), "job2".to_string()).unwrap();

        assert_eq!(manager.count_by_status(JobStatus::Running), 2);
        assert_eq!(manager.count_by_status(JobStatus::Completed), 0);

        manager.get_job(job1).unwrap().complete();

        assert_eq!(manager.count_by_status(JobStatus::Running), 1);
        assert_eq!(manager.count_by_status(JobStatus::Completed), 1);
    }
}

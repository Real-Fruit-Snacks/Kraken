//! Job service implementation

use std::sync::Arc;
use tonic::{Request, Response, Status};

use db::repos::JobRepo;
use protocol::{
    job_service_server::JobService, GetJobOutputRequest, GetJobOutputResponse,
    JobKillRequest, JobKillResponse, JobListRequest, JobListResponse,
};

use super::GrpcError;

/// Job service implementation
pub struct JobServiceImpl {
    job_repo: Arc<JobRepo>,
}

impl JobServiceImpl {
    pub fn new(job_repo: Arc<JobRepo>) -> Self {
        Self { job_repo }
    }
}

#[tonic::async_trait]
impl JobService for JobServiceImpl {
    async fn list_jobs(
        &self,
        _request: Request<JobListRequest>,
    ) -> Result<Response<JobListResponse>, Status> {
        use protocol::{JobInfo, JobStatus};

        // Get all jobs (TODO: filter by implant_id when added to proto)
        let jobs = self.job_repo.list_all(100).await
            .map_err(|e| GrpcError::internal("list_jobs", e.to_string()).to_status())?;

        // Convert to protocol messages
        let job_infos: Vec<JobInfo> = jobs
            .into_iter()
            .map(|row| {
                let status = match row.status.as_str() {
                    "queued" => JobStatus::Running as i32,
                    "dispatched" => JobStatus::Running as i32,
                    "running" => JobStatus::Running as i32,
                    "completed" => JobStatus::Completed as i32,
                    "failed" => JobStatus::Failed as i32,
                    "cancelled" => JobStatus::Cancelled as i32,
                    _ => JobStatus::Running as i32,
                };

                JobInfo {
                    job_id: row.job_id as u32,
                    task_id: row.task_id,
                    description: row.description,
                    status,
                    created_at: row.created_at,
                    completed_at: row.completed_at,
                    progress: row.progress as u32,
                }
            })
            .collect();

        Ok(Response::new(JobListResponse { jobs: job_infos }))
    }

    async fn kill_job(
        &self,
        request: Request<JobKillRequest>,
    ) -> Result<Response<JobKillResponse>, Status> {
        let req = request.into_inner();

        // Update job status to cancelled
        match self
            .job_repo
            .update_status(req.job_id as i64, "cancelled", 0, None, None)
            .await
        {
            Ok(_) => Ok(Response::new(JobKillResponse {
                success: true,
                message: format!("Job {} cancelled", req.job_id),
            })),
            Err(e) => Ok(Response::new(JobKillResponse {
                success: false,
                message: format!("Failed to cancel job: {}", e),
            })),
        }
    }

    async fn get_job_output(
        &self,
        request: Request<GetJobOutputRequest>,
    ) -> Result<Response<GetJobOutputResponse>, Status> {
        let req = request.into_inner();

        // Get job to check status
        let job = self.job_repo.get(req.job_id as i64).await
            .map_err(|e| GrpcError::internal("get_job", e.to_string()).to_status())?
            .ok_or_else(|| GrpcError::not_found("Job", req.job_id.to_string()).to_status())?;

        // Get all output chunks
        let output_chunks = self.job_repo.get_outputs(req.job_id as i64).await
            .map_err(|e| GrpcError::internal("get_job_output", e.to_string()).to_status())?;

        // Determine if job is complete
        let is_complete = matches!(job.status.as_str(), "completed" | "failed" | "cancelled");

        // Map final status
        let final_status = if is_complete {
            let status = match job.status.as_str() {
                "completed" => protocol::JobStatus::Completed as i32,
                "failed" => protocol::JobStatus::Failed as i32,
                "cancelled" => protocol::JobStatus::Cancelled as i32,
                _ => protocol::JobStatus::Running as i32,
            };
            Some(status)
        } else {
            None
        };

        Ok(Response::new(GetJobOutputResponse {
            output_chunks,
            is_complete,
            final_status,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();

        sqlx::query(
            r#"
            CREATE TABLE jobs (
                job_id INTEGER PRIMARY KEY,
                implant_id BLOB NOT NULL,
                task_id BLOB NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL,
                progress INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                completed_at INTEGER,
                error_message TEXT,
                output_size INTEGER NOT NULL DEFAULT 0
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    #[tokio::test]
    async fn test_list_jobs_empty() {
        let pool = setup_test_db().await;
        let job_repo = Arc::new(JobRepo::new(pool));
        let service = JobServiceImpl::new(job_repo);

        let request = Request::new(JobListRequest {});
        let response = service.list_jobs(request).await.unwrap();
        assert_eq!(response.into_inner().jobs.len(), 0);
    }

    #[tokio::test]
    async fn test_kill_job() {
        let pool = setup_test_db().await;
        let job_repo = Arc::new(JobRepo::new(pool));

        // Create a test job
        let job_row = db::repos::JobRow {
            job_id: 1,
            implant_id: vec![1, 2, 3, 4],
            task_id: vec![5, 6, 7, 8],
            description: "test job".to_string(),
            status: "running".to_string(),
            progress: 0,
            created_at: 1000,
            completed_at: None,
            error_message: None,
            output_size: 0,
        };
        job_repo.create(&job_row).await.unwrap();

        let service = JobServiceImpl::new(Arc::clone(&job_repo));
        let request = Request::new(JobKillRequest { job_id: 1 });
        let response = service.kill_job(request).await.unwrap();

        let result = response.into_inner();
        assert!(result.success);

        // Verify status was updated
        let job = job_repo.get(1).await.unwrap().unwrap();
        assert_eq!(job.status, "cancelled");
    }
}

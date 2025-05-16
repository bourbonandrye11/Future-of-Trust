
// Always return healthy status for now
// Later can extend to real checks (DB connection, TEE status, etc.)

use tonic::{Request, Response, Status};
use custody::health_service_server::HealthService;
use custody::{HealthCheckRequest, HealthCheckResponse};

pub mod custody {
    tonic::include_proto!("custody");
}

/// Concrete implementation of the HealthService gRPC interface
#[derive(Default)]
pub struct MyHealthService;

#[tonic::async_trait]
impl HealthService for MyHealthService {
    /// Basic health check endpoint.
    async fn check(
        &self,
        _request: Request<HealthCheckRequest>, // No payload needed
    ) -> Result<Response<HealthCheckResponse>, Status> {
        // Always respond "SERVING" for now (server is healthy)
        let response = HealthCheckResponse {
            status: "SERVING".into(),
        };

        Ok(Response::new(response))
    }
}

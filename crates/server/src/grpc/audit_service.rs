//! AuditService gRPC implementation
//!
//! Exposes the tamper-evident audit chain via gRPC for the web UI and CLI.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use protocol::{
    audit_service_server::AuditService, AuditEvent as ProtoAuditEvent,
    ListAuditEventsRequest, ListAuditEventsResponse, StreamAuditEventsRequest,
    Timestamp, VerifyChainIntegrityRequest, VerifyChainIntegrityResponse,
};

use crate::ServerState;

pub struct AuditServiceImpl {
    state: Arc<ServerState>,
}

impl AuditServiceImpl {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }

    /// Convert an internal AuditEvent to the proto representation
    fn to_proto(event: &kraken_audit::AuditEvent) -> ProtoAuditEvent {
        ProtoAuditEvent {
            event_id: event.id.as_bytes().to_vec(),
            event_type: format!("{:?}", event.category).to_lowercase(),
            operator_id: event
                .operator_id
                .map(|id| id.as_bytes().to_vec())
                .unwrap_or_default(),
            timestamp: Some(Timestamp::from(event.timestamp)),
            previous_hash: event
                .previous_hash
                .as_ref()
                .map(|h| h.as_bytes().to_vec())
                .unwrap_or_default(),
            event_hash: event
                .event_hash
                .as_ref()
                .map(|h| h.as_bytes().to_vec())
                .unwrap_or_default(),
            details: event
                .details
                .as_ref()
                .map(|d| d.to_string())
                .unwrap_or_default(),
        }
    }
}

#[tonic::async_trait]
impl AuditService for AuditServiceImpl {
    async fn list_audit_events(
        &self,
        request: Request<ListAuditEventsRequest>,
    ) -> Result<Response<ListAuditEventsResponse>, Status> {
        let req = request.into_inner();
        let limit = if req.limit == 0 { 100 } else { req.limit as usize };
        let offset = req.offset as usize;

        let all_events = self.state.audit.recent_events(limit + offset);

        // Apply offset
        let events: Vec<_> = all_events
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect();

        // Apply filters
        let filtered: Vec<_> = events
            .iter()
            .filter(|e| {
                if !req.event_type.is_empty() {
                    let etype = format!("{:?}", e.category).to_lowercase();
                    if etype != req.event_type {
                        return false;
                    }
                }
                if !req.operator_id.is_empty() {
                    if let Some(op_id) = e.operator_id {
                        if op_id.as_bytes() != req.operator_id.as_slice() {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                true
            })
            .collect();

        let total_count = filtered.len() as u32;
        let proto_events: Vec<ProtoAuditEvent> =
            filtered.iter().map(|e| Self::to_proto(e)).collect();

        Ok(Response::new(ListAuditEventsResponse {
            events: proto_events,
            total_count,
        }))
    }

    type StreamAuditEventsStream = ReceiverStream<Result<ProtoAuditEvent, Status>>;

    async fn stream_audit_events(
        &self,
        request: Request<StreamAuditEventsRequest>,
    ) -> Result<Response<Self::StreamAuditEventsStream>, Status> {
        let req = request.into_inner();
        let event_type_filter = if req.event_type.is_empty() {
            None
        } else {
            Some(req.event_type)
        };

        let state = Arc::clone(&self.state);
        let (tx, rx) = mpsc::channel(64);

        // Spawn a task that polls for new audit events
        tokio::spawn(async move {
            let mut last_sequence = state.audit.current_sequence();

            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

                let current = state.audit.current_sequence();
                if current > last_sequence {
                    let count = (current - last_sequence) as usize;
                    let new_events = state.audit.recent_events(count);

                    for event in new_events.into_iter().rev() {
                        if event.sequence <= last_sequence {
                            continue;
                        }

                        // Apply filter
                        if let Some(ref filter) = event_type_filter {
                            let etype = format!("{:?}", event.category).to_lowercase();
                            if &etype != filter {
                                continue;
                            }
                        }

                        let proto = AuditServiceImpl::to_proto(&event);
                        if tx.send(Ok(proto)).await.is_err() {
                            return; // Client disconnected
                        }
                    }

                    last_sequence = current;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn verify_chain_integrity(
        &self,
        request: Request<VerifyChainIntegrityRequest>,
    ) -> Result<Response<VerifyChainIntegrityResponse>, Status> {
        let req = request.into_inner();
        let check_count = if req.check_last_n == 0 {
            1000 // Default max
        } else {
            req.check_last_n as usize
        };

        let events = self.state.audit.recent_events(check_count);

        // Events come most-recent-first, reverse for chain verification
        let mut chronological = events;
        chronological.reverse();

        let events_checked = chronological.len() as u32;

        match self.state.audit.verify_chain(&chronological) {
            Ok(()) => Ok(Response::new(VerifyChainIntegrityResponse {
                is_valid: true,
                error_message: String::new(),
                events_checked,
            })),
            Err(e) => Ok(Response::new(VerifyChainIntegrityResponse {
                is_valid: false,
                error_message: e.to_string(),
                events_checked,
            })),
        }
    }
}

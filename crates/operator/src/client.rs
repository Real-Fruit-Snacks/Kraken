//! gRPC client for teamserver

use anyhow::Result;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use common::{ImplantId, TaskId};
use protocol::{
    bof_service_client::BofServiceClient, collab_service_client::CollabServiceClient,
    inject_service_client::InjectServiceClient, job_service_client::JobServiceClient,
    listener_service_client::ListenerServiceClient, operator_service_client::OperatorServiceClient,
    payload_service_client::PayloadServiceClient, proxy_service_client::ProxyServiceClient,
    BofCatalogEntry, BurnImplantRequest, CancelTaskRequest,
    CollabStatsResponse, ComputeRouteRequest, ComputeRouteResponse, ConnectPeerRequest,
    DeleteBofRequest, DeleteImplantRequest, DeletePayloadRequest, DisconnectPeerRequest,
    DispatchTaskRequest, ExecuteBofRequest, ExecuteBofResponse, GeneratePayloadRequest,
    GeneratePayloadResponse, GetBofRequest, GetChatHistoryRequest, GetChatHistoryResponse,
    GetCollabStatsRequest, GetImplantRequest, GetOnlineOperatorsRequest,
    GetPayloadRequest, GetProxyStatsRequest, GetSelfRequest,
    GetSessionLocksRequest, GetTaskRequest, GetTopologyRequest,
    Implant, ImplantServiceClient, InjectRequest, LockSessionRequest, MeshListenRequest,
    InjectResponse, JobInfo, JobKillRequest, JobListRequest, ListBoFsRequest,
    ListImplantsRequest, ListListenersRequest, ListLootRequest, ListModulesRequest,
    ListBofExecutionsRequest, ListBofExecutionsResponse, ListPayloadsRequest,
    ListProcessesRequest, ListProcessesResponse, ListProxiesRequest, ListTasksRequest,
    Listener, LoadModuleRequest, LootEntry, LootServiceClient, MeshServiceClient,
    ModuleInfo, ModuleServiceClient, Operator, OperatorPresence, Payload, ProxyStats,
    RetireImplantRequest, SendChatRequest, SessionLock, SetRoleRequest, StartListenerRequest,
    StartPortForwardRequest, StartProxyRequest, StartProxyResponse, StopListenerRequest,
    StopPortForwardRequest, StopProxyRequest, TaskInfo, TaskServiceClient, UnloadModuleRequest,
    UnlockSessionRequest, UploadBofRequest, Uuid, ValidateBofRequest, ValidateBofResponse,
};

/// gRPC client wrapper
pub struct KrakenClient {
    channel: Channel,
}

impl KrakenClient {
    /// Connect to teamserver
    pub async fn connect(addr: &str, ca_path: Option<&str>, cert_path: Option<&str>, key_path: Option<&str>) -> Result<Self> {
        let channel = if let (Some(ca), Some(cert), Some(key)) = (ca_path, cert_path, key_path) {
            let ca_cert = std::fs::read(ca)?;
            let client_cert = std::fs::read(cert)?;
            let client_key = std::fs::read(key)?;

            let tls = ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(ca_cert))
                .identity(Identity::from_pem(client_cert, client_key));

            let addr = if addr.starts_with("http://") {
                addr.replace("http://", "https://")
            } else {
                addr.to_string()
            };

            Channel::from_shared(addr)?
                .tls_config(tls)?
                .connect()
                .await?
        } else {
            Channel::from_shared(addr.to_string())?.connect().await?
        };

        Ok(Self { channel })
    }

    /// List all implants
    pub async fn list_implants(&self) -> Result<Vec<protocol::Implant>> {
        let mut client = ImplantServiceClient::new(self.channel.clone());

        let request = tonic::Request::new(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        });

        let response = client.list_implants(request).await?;
        Ok(response.into_inner().implants)
    }

    /// Get a specific implant by ID
    pub async fn get_implant(&self, implant_id: Vec<u8>) -> Result<Implant> {
        let mut client = ImplantServiceClient::new(self.channel.clone());

        let request = tonic::Request::new(GetImplantRequest {
            implant_id: Some(Uuid { value: implant_id }),
        });

        let response = client.get_implant(request).await?;
        Ok(response.into_inner())
    }

    /// Burn an implant (self-destruct)
    #[allow(dead_code)]
    pub async fn burn_implant(&self, implant_id: Vec<u8>, reason: String) -> Result<Implant> {
        let mut client = ImplantServiceClient::new(self.channel.clone());

        let request = tonic::Request::new(BurnImplantRequest {
            implant_id: Some(Uuid { value: implant_id }),
            reason,
        });

        let response = client.burn_implant(request).await?;
        Ok(response.into_inner())
    }

    /// Retire an implant (mark as inactive)
    pub async fn retire_implant(&self, implant_id: Vec<u8>) -> Result<Implant> {
        let mut client = ImplantServiceClient::new(self.channel.clone());

        let request = tonic::Request::new(RetireImplantRequest {
            implant_id: Some(Uuid { value: implant_id }),
        });

        let response = client.retire_implant(request).await?;
        Ok(response.into_inner())
    }

    /// Update implant configuration (name, tags, checkin interval, jitter)
    pub async fn update_implant(
        &self,
        implant_id: Vec<u8>,
        name: Option<String>,
        tags: Vec<String>,
        notes: Option<String>,
        checkin_interval: Option<u32>,
        jitter_percent: Option<u32>,
    ) -> Result<Implant> {
        let mut client = ImplantServiceClient::new(self.channel.clone());

        let request = tonic::Request::new(protocol::UpdateImplantRequest {
            implant_id: Some(Uuid { value: implant_id }),
            name,
            tags,
            notes,
            checkin_interval,
            jitter_percent,
        });

        let response = client.update_implant(request).await?;
        Ok(response.into_inner())
    }

    /// Delete an implant from database
    pub async fn delete_implant(&self, implant_id: Vec<u8>) -> Result<bool> {
        let mut client = ImplantServiceClient::new(self.channel.clone());

        let request = tonic::Request::new(DeleteImplantRequest {
            implant_id: Some(Uuid { value: implant_id }),
        });

        let response = client.delete_implant(request).await?;
        Ok(response.into_inner().success)
    }

    /// List all loot entries (optionally filtered by type)
    pub async fn list_loot(&self, type_filter: Option<i32>) -> Result<Vec<LootEntry>> {
        let mut client = LootServiceClient::new(self.channel.clone());

        let request = tonic::Request::new(ListLootRequest {
            implant_id: None,
            type_filter,
            limit: None,
            offset: None,
        });

        let response = client.list_loot(request).await?;
        Ok(response.into_inner().entries)
    }

    /// Search loot using server-side FTS5 full-text search
    pub async fn search_loot(&self, query: String, limit: Option<i32>) -> Result<protocol::SearchLootResponse> {
        let mut client = LootServiceClient::new(self.channel.clone());

        let request = tonic::Request::new(protocol::SearchLootRequest {
            query,
            limit: limit.unwrap_or(100),
        });

        let response = client.search_loot(request).await?;
        Ok(response.into_inner())
    }

    /// Get a specific loot entry by ID
    pub async fn get_loot(&self, loot_id: Vec<u8>) -> Result<LootEntry> {
        let mut client = LootServiceClient::new(self.channel.clone());

        let request = tonic::Request::new(protocol::GetLootRequest {
            loot_id: Some(Uuid { value: loot_id }),
        });

        let response = client.get_loot(request).await?;
        Ok(response.into_inner())
    }

    /// Export loot to structured format
    pub async fn export_loot(&self, format: String, type_filter: Option<i32>) -> Result<protocol::ExportLootResponse> {
        let mut client = LootServiceClient::new(self.channel.clone());

        let request = tonic::Request::new(protocol::ExportLootRequest {
            implant_id: None,
            type_filter,
            format,
        });

        let response = client.export_loot(request).await?;
        Ok(response.into_inner())
    }

    /// Delete a loot entry
    pub async fn delete_loot(&self, loot_id: Vec<u8>) -> Result<bool> {
        let mut client = LootServiceClient::new(self.channel.clone());

        let request = tonic::Request::new(protocol::DeleteLootRequest {
            loot_id: Some(Uuid { value: loot_id }),
        });

        let response = client.delete_loot(request).await?;
        Ok(response.into_inner().success)
    }

    /// List available modules from the server
    pub async fn list_modules(&self) -> Result<Vec<ModuleInfo>> {
        let mut client = ModuleServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(ListModulesRequest {});
        let response = client.list_modules(request).await?;
        Ok(response.into_inner().modules)
    }

    /// Load a module onto an implant
    pub async fn load_module(
        &self,
        implant_id: ImplantId,
        module_id: &str,
        version: Option<String>,
    ) -> Result<()> {
        let mut client = ModuleServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(LoadModuleRequest {
            implant_id: implant_id.as_bytes().to_vec(),
            module_id: module_id.to_string(),
            version,
        });
        client.load_module(request).await?;
        Ok(())
    }

    /// Unload a module from an implant
    pub async fn unload_module(&self, implant_id: ImplantId, module_id: &str) -> Result<()> {
        let mut client = ModuleServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(UnloadModuleRequest {
            implant_id: implant_id.as_bytes().to_vec(),
            module_id: module_id.to_string(),
        });
        client.unload_module(request).await?;
        Ok(())
    }

    /// Get current mesh topology from the server
    pub async fn get_mesh_topology(
        &self,
    ) -> Result<protocol::MeshTopology> {
        let mut client = MeshServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(GetTopologyRequest {});
        let response = client.get_topology(request).await?;
        Ok(response.into_inner())
    }

    /// Connect implant to mesh peer
    pub async fn connect_peer(
        &self,
        implant_id: Vec<u8>,
        peer_id: Vec<u8>,
        transport: i32,
        address: String,
        port: u32,
        pipe_name: String,
    ) -> Result<Vec<u8>> {
        let mut client = MeshServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(ConnectPeerRequest {
            implant_id,
            peer_id,
            transport,
            address,
            port,
            pipe_name,
        });
        let response = client.connect_peer(request).await?;
        Ok(response.into_inner().task_id.map(|t| t.value).unwrap_or_default())
    }

    /// Disconnect implant from mesh peer
    pub async fn disconnect_peer(
        &self,
        implant_id: Vec<u8>,
        peer_id: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let mut client = MeshServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(DisconnectPeerRequest {
            implant_id,
            peer_id,
        });
        let response = client.disconnect_peer(request).await?;
        Ok(response.into_inner().task_id.map(|t| t.value).unwrap_or_default())
    }

    /// Set mesh role for implant
    pub async fn set_mesh_role(
        &self,
        implant_id: Vec<u8>,
        role: i32,
    ) -> Result<Vec<u8>> {
        let mut client = MeshServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(SetRoleRequest {
            implant_id,
            role,
        });
        let response = client.set_role(request).await?;
        Ok(response.into_inner().task_id.map(|t| t.value).unwrap_or_default())
    }

    /// Start mesh listener on implant
    pub async fn mesh_listen(
        &self,
        implant_id: Vec<u8>,
        port: u32,
        transport: i32,
        bind_address: String,
    ) -> Result<Vec<u8>> {
        let mut client = MeshServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(MeshListenRequest {
            implant_id,
            port,
            transport,
            bind_address,
        });
        let response = client.listen(request).await?;
        Ok(response.into_inner().task_id.map(|t| t.value).unwrap_or_default())
    }

    /// Compute route between mesh nodes
    pub async fn compute_route(
        &self,
        from_id: Vec<u8>,
        to_id: Vec<u8>,
        max_paths: u32,
    ) -> Result<ComputeRouteResponse> {
        let mut client = MeshServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(ComputeRouteRequest {
            from_id,
            to_id,
            max_paths,
        });
        let response = client.compute_route(request).await?;
        Ok(response.into_inner())
    }

    /// Get current operator information
    pub async fn get_self(&self) -> Result<Operator> {
        let mut client = OperatorServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(GetSelfRequest {});
        let response = client.get_self(request).await?;
        Ok(response.into_inner())
    }

    /// Dispatch a task
    pub async fn dispatch_task(
        &self,
        implant_id: ImplantId,
        task_type: &str,
        task_data: Vec<u8>,
    ) -> Result<TaskId> {
        let mut client = TaskServiceClient::new(self.channel.clone());

        let request = tonic::Request::new(DispatchTaskRequest {
            implant_id: Some(Uuid {
                value: implant_id.as_bytes().to_vec(),
            }),
            task_type: task_type.to_string(),
            task_data,
        });

        let response = client.dispatch_task(request).await?;
        let task_uuid = response
            .into_inner()
            .task_id
            .ok_or_else(|| anyhow::anyhow!("no task_id in response"))?;

        TaskId::from_bytes(&task_uuid.value).map_err(|e| anyhow::anyhow!("invalid task_id: {}", e))
    }

    /// List background jobs for an implant
    pub async fn list_jobs(&self, _implant_id: &[u8]) -> Result<Vec<JobInfo>> {
        let mut client = JobServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(JobListRequest {});
        let response = client.list_jobs(request).await?;

        // Filter to only jobs for this implant
        // TODO: Add implant_id to JobListRequest proto and filter server-side
        let all_jobs = response.into_inner().jobs;
        Ok(all_jobs)
    }

    /// Kill a background job
    pub async fn kill_job(&self, _implant_id: &[u8], job_id: u32) -> Result<bool> {
        let mut client = JobServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(JobKillRequest { job_id });
        let response = client.kill_job(request).await?;
        Ok(response.into_inner().success)
    }

    /// Get job output
    pub async fn get_job_output(&self, job_id: u32) -> Result<(Vec<Vec<u8>>, bool, Option<i32>)> {
        let mut client = JobServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(protocol::GetJobOutputRequest { job_id });
        let response = client.get_job_output(request).await?;
        let inner = response.into_inner();
        Ok((inner.output_chunks, inner.is_complete, inner.final_status))
    }

    /// List all listeners
    pub async fn list_listeners(&self) -> Result<Vec<Listener>> {
        let mut client = ListenerServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(ListListenersRequest {});
        let response = client.list_listeners(request).await?;
        Ok(response.into_inner().listeners)
    }

    /// Start a new listener
    pub async fn start_listener(
        &self,
        listener_type: String,
        bind_host: String,
        bind_port: u32,
        profile_id: Option<String>,
        tls_cert_path: Option<String>,
        tls_key_path: Option<String>,
        dns_domain: Option<String>,
    ) -> Result<Listener> {
        let mut client = ListenerServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(StartListenerRequest {
            listener_type,
            bind_host,
            bind_port,
            profile_id: profile_id.unwrap_or_else(|| "default".to_string()),
            tls_cert_path,
            tls_key_path,
            dns_domain,
        });
        let response = client.start_listener(request).await?;
        Ok(response.into_inner())
    }

    /// Stop a listener
    pub async fn stop_listener(&self, listener_id: Vec<u8>) -> Result<Listener> {
        let mut client = ListenerServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(StopListenerRequest {
            listener_id: Some(Uuid { value: listener_id }),
        });
        let response = client.stop_listener(request).await?;
        Ok(response.into_inner())
    }

    /// List tasks (optionally filtered by implant or status)
    pub async fn list_tasks(
        &self,
        implant_id: Option<Vec<u8>>,
        status_filter: Option<i32>,
        limit: Option<u32>,
    ) -> Result<Vec<TaskInfo>> {
        let mut client = TaskServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(ListTasksRequest {
            implant_id: implant_id.map(|id| Uuid { value: id }),
            status_filter,
            limit,
        });
        let response = client.list_tasks(request).await?;
        Ok(response.into_inner().tasks)
    }

    /// Get a specific task by ID
    pub async fn get_task(&self, task_id: Vec<u8>) -> Result<TaskInfo> {
        let mut client = TaskServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(GetTaskRequest {
            task_id: Some(Uuid { value: task_id }),
        });
        let response = client.get_task(request).await?;
        Ok(response.into_inner())
    }

    /// Cancel a queued or running task
    pub async fn cancel_task(&self, task_id: Vec<u8>) -> Result<TaskInfo> {
        let mut client = TaskServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(CancelTaskRequest {
            task_id: Some(Uuid { value: task_id }),
        });
        let response = client.cancel_task(request).await?;
        Ok(response.into_inner())
    }

    /// List processes on target implant
    pub async fn list_processes(
        &self,
        implant_id: Vec<u8>,
        include_system: bool,
        name_filter: Option<String>,
    ) -> Result<ListProcessesResponse> {
        let mut client = InjectServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(ListProcessesRequest {
            implant_id: Some(Uuid { value: implant_id }),
            include_system,
            name_filter: name_filter.unwrap_or_default(),
        });
        let response = client.list_processes(request).await?;
        Ok(response.into_inner())
    }

    /// Inject shellcode into target process
    pub async fn inject_shellcode(
        &self,
        implant_id: Vec<u8>,
        target_pid: u32,
        shellcode: Vec<u8>,
        method: i32,
        wait_for_completion: bool,
        timeout_ms: u32,
    ) -> Result<InjectResponse> {
        let mut client = InjectServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(InjectRequest {
            implant_id: Some(Uuid { value: implant_id }),
            target_pid,
            shellcode,
            method,
            wait_for_completion,
            timeout_ms,
        });
        let response = client.inject(request).await?;
        Ok(response.into_inner())
    }

    /// List BOFs in catalog
    pub async fn list_bofs(&self) -> Result<Vec<BofCatalogEntry>> {
        let mut client = BofServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(ListBoFsRequest {
            category: None,
            search: None,
            tags: vec![],
        });
        let response = client.list_bo_fs(request).await?;
        Ok(response.into_inner().bofs)
    }

    /// Get BOF details by ID
    pub async fn get_bof(&self, bof_id: String) -> Result<BofCatalogEntry> {
        let mut client = BofServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(GetBofRequest { bof_id });
        let response = client.get_bof(request).await?;
        Ok(response.into_inner())
    }

    /// Upload BOF to catalog (simplified - just manifest and data)
    #[allow(dead_code)]
    pub async fn upload_bof(
        &self,
        manifest: protocol::BofManifest,
        x64_data: Option<Vec<u8>>,
        x86_data: Option<Vec<u8>>,
    ) -> Result<String> {
        let mut client = BofServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(UploadBofRequest {
            manifest: Some(manifest),
            x64_data,
            x86_data,
        });
        let response = client.upload_bof(request).await?;
        let result = response.into_inner();
        if !result.success {
            return Err(anyhow::anyhow!(result.error.unwrap_or_else(|| "Upload failed".to_string())));
        }
        Ok(result.bof_id)
    }

    /// Execute BOF on implant
    pub async fn execute_bof(
        &self,
        implant_id: Vec<u8>,
        bof_id: String,
        arguments: Vec<String>,
    ) -> Result<ExecuteBofResponse> {
        let mut client = BofServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(ExecuteBofRequest {
            implant_id: Some(Uuid { value: implant_id }),
            bof_id,
            arguments,
            arch_override: None,
        });
        let response = client.execute_bof(request).await?;
        Ok(response.into_inner())
    }

    /// Delete BOF from catalog
    pub async fn delete_bof(&self, bof_id: String) -> Result<bool> {
        let mut client = BofServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(DeleteBofRequest { bof_id });
        let response = client.delete_bof(request).await?;
        Ok(response.into_inner().success)
    }

    /// Validate BOF compatibility with implant
    pub async fn validate_bof(&self, implant_id: Vec<u8>, bof_id: String) -> Result<ValidateBofResponse> {
        let mut client = BofServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(ValidateBofRequest {
            implant_id: Some(Uuid { value: implant_id }),
            bof_id,
        });
        let response = client.validate_bof(request).await?;
        Ok(response.into_inner())
    }

    /// List recent BOF executions
    pub async fn list_bof_executions(
        &self,
        implant_id: Option<Vec<u8>>,
        bof_id: Option<String>,
        limit: u32,
    ) -> Result<ListBofExecutionsResponse> {
        let mut client = BofServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(ListBofExecutionsRequest {
            implant_id: implant_id.map(|id| Uuid { value: id }),
            bof_id,
            limit,
        });
        let response = client.list_executions(request).await?;
        Ok(response.into_inner())
    }

    /// Generate a new payload
    pub async fn generate_payload(
        &self,
        name: String,
        os: String,
        arch: String,
        format: String,
        listener_id: Vec<u8>,
        c2_endpoints: Vec<String>,
    ) -> Result<GeneratePayloadResponse> {
        let mut client = PayloadServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(GeneratePayloadRequest {
            name,
            os,
            arch,
            format,
            transport: "http".to_string(), // default
            listener_id,
            c2_endpoints,
            obfuscation: true,
            anti_debug: true,
            anti_sandbox: true,
            sleep_mask: true,
            jitter: 20,
            sleep_time: 60,
            kill_date: String::new(),
            working_hours: None,
        });
        let response = client.generate_payload(request).await?;
        Ok(response.into_inner())
    }

    /// List all generated payloads
    pub async fn list_payloads(&self) -> Result<Vec<Payload>> {
        let mut client = PayloadServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(ListPayloadsRequest {});
        let response = client.list_payloads(request).await?;
        Ok(response.into_inner().payloads)
    }

    /// Get a specific payload by ID
    pub async fn get_payload(&self, payload_id: Vec<u8>) -> Result<Payload> {
        let mut client = PayloadServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(GetPayloadRequest { payload_id });
        let response = client.get_payload(request).await?;
        Ok(response.into_inner())
    }

    /// Delete a payload
    pub async fn delete_payload(&self, payload_id: Vec<u8>) -> Result<bool> {
        let mut client = PayloadServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(DeletePayloadRequest { payload_id });
        let response = client.delete_payload(request).await?;
        Ok(response.into_inner().success)
    }

    /// Start a port forward
    pub async fn start_port_forward(
        &self,
        implant_id: Vec<u8>,
        local_host: String,
        local_port: u32,
        remote_host: String,
        remote_port: u32,
        reverse: bool,
    ) -> Result<protocol::StartPortForwardResponse> {
        let mut client = ProxyServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(StartPortForwardRequest {
            implant_id: Some(Uuid { value: implant_id }),
            local_host,
            local_port,
            remote_host,
            remote_port,
            reverse,
        });
        let response = client.start_port_forward(request).await?;
        Ok(response.into_inner())
    }

    /// Stop a port forward
    pub async fn stop_port_forward(&self, forward_id: Vec<u8>) -> Result<bool> {
        let mut client = ProxyServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(StopPortForwardRequest {
            forward_id: Some(Uuid { value: forward_id }),
        });
        let response = client.stop_port_forward(request).await?;
        Ok(response.into_inner().success)
    }

    /// List proxies and port forwards
    pub async fn list_proxies(&self, implant_id: Option<Vec<u8>>) -> Result<protocol::ListProxiesResponse> {
        let mut client = ProxyServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(ListProxiesRequest {
            implant_id: implant_id.map(|id| Uuid { value: id }),
            state: None,
        });
        let response = client.list_proxies(request).await?;
        Ok(response.into_inner())
    }

    /// Start SOCKS proxy on implant
    pub async fn start_proxy(
        &self,
        implant_id: Vec<u8>,
        bind_host: String,
        bind_port: u32,
        version: i32,
        reverse: bool,
    ) -> Result<StartProxyResponse> {
        let mut client = ProxyServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(StartProxyRequest {
            implant_id: Some(Uuid { value: implant_id }),
            bind_host,
            bind_port,
            version,
            username: None,
            password: None,
            reverse,
            connect_timeout: 30,
            allow_dns: true,
        });
        let response = client.start_proxy(request).await?;
        Ok(response.into_inner())
    }

    /// Stop SOCKS proxy
    pub async fn stop_proxy(&self, proxy_id: Vec<u8>) -> Result<bool> {
        let mut client = ProxyServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(StopProxyRequest {
            proxy_id: Some(Uuid { value: proxy_id }),
        });
        let response = client.stop_proxy(request).await?;
        Ok(response.into_inner().success)
    }

    /// Get detailed SOCKS proxy statistics
    pub async fn get_proxy_stats(&self, proxy_id: Vec<u8>) -> Result<ProxyStats> {
        let mut client = ProxyServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(GetProxyStatsRequest {
            proxy_id: Some(Uuid { value: proxy_id }),
        });
        let response = client.get_proxy_stats(request).await?;
        Ok(response.into_inner())
    }

    /// Get online operators
    pub async fn get_online_operators(&self) -> Result<Vec<OperatorPresence>> {
        let mut client = CollabServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(GetOnlineOperatorsRequest {});
        let response = client.get_online_operators(request).await?;
        Ok(response.into_inner().operators)
    }

    /// Lock a session
    pub async fn lock_session(&self, session_id: Vec<u8>, reason: Option<String>) -> Result<SessionLock> {
        let mut client = CollabServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(LockSessionRequest {
            session_id: Some(Uuid { value: session_id }),
            reason,
        });
        let response = client.lock_session(request).await?;
        Ok(response.into_inner())
    }

    /// Unlock a session
    pub async fn unlock_session(&self, session_id: Vec<u8>) -> Result<SessionLock> {
        let mut client = CollabServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(UnlockSessionRequest {
            session_id: Some(Uuid { value: session_id }),
        });
        let response = client.unlock_session(request).await?;
        Ok(response.into_inner())
    }

    /// Get all session locks
    pub async fn get_session_locks(&self) -> Result<Vec<SessionLock>> {
        let mut client = CollabServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(GetSessionLocksRequest {});
        let response = client.get_session_locks(request).await?;
        Ok(response.into_inner().locks)
    }

    /// Send chat message
    pub async fn send_chat(&self, message: String, session_id: Option<Vec<u8>>) -> Result<()> {
        let mut client = CollabServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(SendChatRequest {
            message,
            session_id: session_id.map(|id| Uuid { value: id }),
        });
        let _ = client.send_chat(request).await?;
        Ok(())
    }

    /// Get chat history
    pub async fn get_chat_history(&self, session_id: Option<Vec<u8>>, limit: u32) -> Result<GetChatHistoryResponse> {
        let mut client = CollabServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(GetChatHistoryRequest {
            session_id: session_id.map(|id| Uuid { value: id }),
            limit,
            before: None,
        });
        let response = client.get_chat_history(request).await?;
        Ok(response.into_inner())
    }

    /// Get collaboration statistics
    pub async fn get_collab_stats(&self) -> Result<CollabStatsResponse> {
        let mut client = CollabServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(GetCollabStatsRequest {});
        let response = client.get_stats(request).await?;
        Ok(response.into_inner())
    }

    /// List all operators
    pub async fn list_operators(&self) -> Result<Vec<Operator>> {
        let mut client = OperatorServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(protocol::ListOperatorsRequest {});
        let response = client.list_operators(request).await?;
        Ok(response.into_inner().operators)
    }

    /// Create a new operator
    pub async fn create_operator(&self, username: String, password: String, role: String) -> Result<Operator> {
        let mut client = OperatorServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(protocol::CreateOperatorRequest {
            username,
            password,
            role,
        });
        let response = client.create_operator(request).await?;
        Ok(response.into_inner())
    }

    /// Update an operator
    pub async fn update_operator(&self, operator_id: Vec<u8>, role: Option<String>, disabled: Option<bool>) -> Result<Operator> {
        let mut client = OperatorServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(protocol::UpdateOperatorRequest {
            operator_id,
            role,
            disabled,
        });
        let response = client.update_operator(request).await?;
        Ok(response.into_inner())
    }

    /// Delete an operator
    pub async fn delete_operator(&self, operator_id: Vec<u8>) -> Result<bool> {
        let mut client = OperatorServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(protocol::DeleteOperatorRequest {
            operator_id,
        });
        let response = client.delete_operator(request).await?;
        Ok(response.into_inner().success)
    }

    /// Generate a report
    pub async fn generate_report(&self, title: String, report_type: String, output_format: String) -> Result<(protocol::ReportRecord, Vec<u8>)> {
        let mut client = protocol::report_service_client::ReportServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(protocol::GenerateReportRequest {
            title,
            report_type,
            output_format,
            start_date: None,
            end_date: None,
            include_sessions: true,
            include_tasks: true,
            include_loot: true,
            include_timeline: true,
            include_iocs: true,
        });
        let response = client.generate_report(request).await?;
        let inner = response.into_inner();
        let report = inner.report.unwrap_or_default();
        Ok((report, inner.content))
    }

    /// List all reports
    pub async fn list_reports(&self) -> Result<Vec<protocol::ReportRecord>> {
        let mut client = protocol::report_service_client::ReportServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(protocol::ListReportsRequest {});
        let response = client.list_reports(request).await?;
        Ok(response.into_inner().reports)
    }

    /// Get a specific report
    pub async fn get_report(&self, report_id: Vec<u8>) -> Result<protocol::ReportRecord> {
        let mut client = protocol::report_service_client::ReportServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(protocol::GetReportRequest { report_id });
        let response = client.get_report(request).await?;
        Ok(response.into_inner())
    }

    /// Delete a report
    pub async fn delete_report(&self, report_id: Vec<u8>) -> Result<bool> {
        let mut client = protocol::report_service_client::ReportServiceClient::new(self.channel.clone());
        let request = tonic::Request::new(protocol::DeleteReportRequest { report_id });
        let response = client.delete_report(request).await?;
        Ok(response.into_inner().success)
    }
}

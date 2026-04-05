// Service clients
export {
  createClient,
  implantClient,
  taskClient,
  listenerClient,
  operatorClient,
  lootClient,
  moduleClient,
  meshClient,
  collabClient,
  proxyClient,
  bofClient,
  injectClient,
  payloadClient,
  reportClient,
} from "./client.js";

// Transport
export { createTransport, transport } from "./transport.js";

// Commonly used types from generated protobuf
export {
  // Enums
  TaskStatus,
  LootType,
  MeshTransportType,
  MeshRoleType,
  MeshLinkState,
  ImplantState,

  // Core entities
  Implant,
  Listener,
  Operator,
  TaskInfo,
  LootEntry,

  // Request/Response types - Implant
  ListImplantsRequest,
  ListImplantsResponse,
  GetImplantRequest,
  UpdateImplantRequest,
  BurnImplantRequest,
  RetireImplantRequest,
  StreamImplantEventsRequest,
  ImplantEvent,

  // Request/Response types - Task
  DispatchTaskRequest,
  DispatchTaskResponse,
  GetTaskRequest,
  ListTasksRequest,
  ListTasksResponse,
  CancelTaskRequest,
  StreamTaskResultsRequest,
  TaskResultEvent,

  // Request/Response types - Listener
  StartListenerRequest,
  StopListenerRequest,
  ListListenersRequest,
  ListListenersResponse,

  // Request/Response types - Operator
  GetSelfRequest,
  ListOperatorsRequest,
  ListOperatorsResponse,

  // Request/Response types - Loot
  StoreLootRequest,
  StoreLootResponse,
  GetLootRequest,
  ListLootRequest,
  ListLootResponse,
  DeleteLootRequest,
  DeleteLootResponse,
  ExportLootRequest,
  ExportLootResponse,
  SearchLootRequest,
  SearchLootResponse,

  // Request/Response types - Module
  ListModulesRequest,
  ListModulesResponse,
  LoadModuleRequest,
  UnloadModuleRequest,

  // Request/Response types - Mesh
  GetTopologyRequest,
  MeshTopology,
  MeshNode,
  MeshLink,
  StreamTopologyRequest,
  MeshTopologyUpdate,
  ConnectPeerRequest,
  DisconnectPeerRequest,
  SetRoleRequest,
  MeshListenRequest,
  ComputeRouteRequest,
  ComputeRouteResponse,

  // Request/Response types - Collab
  StreamCollabEventsRequest,
  CollabEvent,
  GetOnlineOperatorsRequest,
  GetOnlineOperatorsResponse,
  SetActiveSessionRequest,
  OperatorPresence,
  LockSessionRequest,
  UnlockSessionRequest,
  GetSessionLocksRequest,
  GetSessionLocksResponse,
  SendChatRequest,
  ChatMessageEvent,
  GetCollabStatsRequest,
  CollabStatsResponse,
  SessionLock,

  // Loot subtypes
  CredentialLoot,
  HashLoot,
  TokenLoot,
  FileLoot,

  // Module info
  ModuleInfo,
  LoadedModuleInfo,

  // Request/Response types - Proxy
  SocksVersion,
  ProxyState,
  SocksProxy,
  PortForward,
  StartProxyRequest,
  StartProxyResponse,
  StopProxyRequest,
  StopProxyResponse,
  ListProxiesRequest,
  ListProxiesResponse,
  GetProxyStatsRequest,
  ProxyStats,
  ProxyConnection,
  StreamProxyStatsRequest,
  ProxyStatsUpdate,
  StartPortForwardRequest,
  StartPortForwardResponse,
  StopPortForwardRequest,
  StopPortForwardResponse,

  // Request/Response types - BOF
  BOFCategory,
  BOFArgType,
  BOFArgument,
  BOFManifest,
  BOFCatalogEntry,
  BOFExecution,
  ListBOFsRequest,
  ListBOFsResponse,
  GetBOFRequest,
  ExecuteBOFRequest,
  ExecuteBOFResponse,
  ValidateBOFRequest,
  ValidateBOFResponse,
  ListBOFExecutionsRequest,
  ListBOFExecutionsResponse,
  UploadBOFRequest,
  UploadBOFResponse,
  DeleteBOFRequest,
  DeleteBOFResponse,

  // Request/Response types - Payload
  WorkingHours,
  GeneratePayloadRequest,
  GeneratePayloadResponse,
  Payload,
  ListPayloadsRequest,
  ListPayloadsResponse,
  GetPayloadRequest,
  DeletePayloadRequest,
  DeletePayloadResponse,

  // Request/Response types - Report
  ReportRecord,
  GenerateReportRequest,
  GenerateReportResponse,
  ListReportsRequest,
  ListReportsResponse,
  GetReportRequest,
  DeleteReportRequest,
  DeleteReportResponse,
} from "../gen/kraken_pb.js";

import { createClient } from "@connectrpc/connect";
import {
  ImplantService,
  TaskService,
  ListenerService,
  OperatorService,
  LootService,
  ModuleService,
  MeshService,
  CollabService,
  ProxyService,
  BOFService,
  InjectService,
  PayloadService,
  ReportService,
  JobService,
} from "../gen/kraken_connect.js";
import { transport } from "./transport.js";

export { createClient };

export const implantClient = createClient(ImplantService, transport);
export const taskClient = createClient(TaskService, transport);
export const listenerClient = createClient(ListenerService, transport);
export const operatorClient = createClient(OperatorService, transport);
export const lootClient = createClient(LootService, transport);
export const moduleClient = createClient(ModuleService, transport);
export const meshClient = createClient(MeshService, transport);
export const collabClient = createClient(CollabService, transport);
export const proxyClient = createClient(ProxyService, transport);
export const bofClient = createClient(BOFService, transport);
export const injectClient = createClient(InjectService, transport);
export const payloadClient = createClient(PayloadService, transport);
export const reportClient = createClient(ReportService, transport);
export const jobClient = createClient(JobService, transport);

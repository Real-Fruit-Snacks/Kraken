import { createConnectTransport, createGrpcWebTransport } from "@connectrpc/connect-web";
import type { Transport } from "@connectrpc/connect";

const DEFAULT_API_URL = "http://localhost:8081";

export function createTransport(): Transport {
  const baseUrl = import.meta.env.VITE_API_URL ?? DEFAULT_API_URL;
  const useConnect = import.meta.env.VITE_USE_CONNECT === "true";

  if (useConnect) {
    return createConnectTransport({ baseUrl });
  }

  return createGrpcWebTransport({ baseUrl });
}

export const transport = createTransport();

import { writable, get } from "svelte/store";
import { apiUrl } from "../lib/apiPath";

export type UIAuthState = { enabled: boolean; authenticated: boolean; loading: boolean };
export const uiAuth = writable<UIAuthState>({ enabled: false, authenticated: false, loading: true });

export async function checkUIAuth(): Promise<UIAuthState> {
  try {
    const response = await fetch(apiUrl("/api/ui-auth/status"));
    if (!response.ok) throw new Error(`Status request failed (${response.status})`);
    const status = await response.json() as { enabled: boolean; authenticated: boolean };
    const state = { ...status, loading: false };
    uiAuth.set(state);
    return state;
  } catch (error) {
    uiAuth.set({ enabled: true, authenticated: false, loading: false });
    throw error;
  }
}

export async function submitUIAuth(path: "setup" | "login", body: Record<string, string>, apiKey?: string): Promise<void> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey) headers.Authorization = `Bearer ${apiKey}`;
  const response = await fetch(apiUrl(`/api/ui-auth/${path}`), {
    method: "POST", headers, body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error((await response.text()) || `Request failed (${response.status})`);
  await checkUIAuth();
}

export async function logoutUIAuth(): Promise<void> {
  const response = await fetch(apiUrl("/api/ui-auth/logout"), { method: "POST" });
  if (!response.ok) throw new Error(`Sign out failed (${response.status})`);
  await checkUIAuth();
}

export function uiAuthEnabled(): boolean { return get(uiAuth).enabled; }

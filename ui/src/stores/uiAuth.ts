import { writable } from "svelte/store";
import { apiUrl } from "../lib/apiPath";

export type UIAuthState = { required: boolean; authenticated: boolean; loading: boolean };
export const uiAuth = writable<UIAuthState>({ required: false, authenticated: true, loading: true });

export async function checkUIAuth(): Promise<UIAuthState> {
  try {
    const response = await fetch(apiUrl("/api/ui-auth/status"));
    if (!response.ok) throw new Error(`Status request failed (${response.status})`);
    const status = await response.json() as { required: boolean; authenticated: boolean };
    const state = { ...status, loading: false };
    uiAuth.set(state);
    return state;
  } catch (error) {
    uiAuth.set({ required: true, authenticated: false, loading: false });
    throw error;
  }
}

export async function submitUIAuth(apiKey: string): Promise<void> {
  const response = await fetch(apiUrl("/api/ui-auth/login"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ apiKey }),
  });
  if (!response.ok) throw new Error((await response.text()) || `Sign-in failed (${response.status})`);
  await checkUIAuth();
}

export async function logoutUIAuth(): Promise<void> {
  const response = await fetch(apiUrl("/api/ui-auth/logout"), { method: "POST" });
  if (!response.ok) throw new Error(`Sign out failed (${response.status})`);
  await checkUIAuth();
}

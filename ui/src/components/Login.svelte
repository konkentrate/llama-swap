<script lang="ts">
  import { submitUIAuth } from "../stores/uiAuth";

  let username = $state("");
  let password = $state("");
  let error = $state("");
  let busy = $state(false);

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    busy = true;
    error = "";
    try {
      await submitUIAuth("login", { username, password });
      password = "";
    } catch (e) {
      error = e instanceof Error ? e.message : "Sign in failed";
    } finally {
      busy = false;
    }
  }
</script>

<main class="flex min-h-screen items-center justify-center bg-muted/30 p-4">
  <form class="w-full max-w-sm space-y-4 rounded-xl border bg-background p-6 shadow-sm" onsubmit={submit}>
    <div><h1 class="text-xl font-semibold">Sign in</h1><p class="mt-1 text-sm text-muted-foreground">Enter your UI credentials to continue.</p></div>
    <label class="block space-y-1 text-sm">Username<input class="w-full rounded-md border bg-background px-3 py-2" autocomplete="username" bind:value={username} required /></label>
    <label class="block space-y-1 text-sm">Password<input class="w-full rounded-md border bg-background px-3 py-2" type="password" autocomplete="current-password" bind:value={password} required /></label>
    {#if error}<p role="alert" class="text-sm text-destructive">{error}</p>{/if}
    <button class="w-full rounded-md bg-primary px-3 py-2 text-primary-foreground disabled:opacity-50" disabled={busy}>{busy ? "Signing in..." : "Sign in"}</button>
  </form>
</main>

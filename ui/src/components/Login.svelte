<script lang="ts">
  import { submitUIAuth } from "../stores/uiAuth";

  let apiKey = $state("");
  let error = $state("");
  let busy = $state(false);

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    busy = true;
    error = "";
    try {
      await submitUIAuth(apiKey);
      apiKey = "";
    } catch (e) {
      error = e instanceof Error ? e.message : "Sign in failed";
    } finally {
      busy = false;
    }
  }
</script>

<main class="flex min-h-screen items-center justify-center bg-muted/30 p-4">
  <form class="w-full max-w-sm space-y-4 rounded-xl border bg-background p-6 shadow-sm" onsubmit={submit}>
    <div>
      <h1 class="text-xl font-semibold">Sign in</h1>
      <p class="mt-1 text-sm text-muted-foreground">Enter an API key configured for llama-swap.</p>
    </div>
    <label class="block space-y-1 text-sm">
      API key
      <input
        class="w-full rounded-md border bg-background px-3 py-2"
        type="password"
        name="password"
        autocomplete="current-password"
        bind:value={apiKey}
        required
      />
    </label>
    {#if error}<p role="alert" class="text-sm text-destructive">{error}</p>{/if}
    <button class="w-full rounded-md bg-primary px-3 py-2 text-primary-foreground disabled:opacity-50" disabled={busy}>
      {busy ? "Signing in..." : "Sign in"}
    </button>
  </form>
</main>

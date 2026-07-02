// Bootstrap helpers
//
// ensureBootstrapAdmin: ensures an initial admin account exists.
//
// On the first request after deployment, if ADMIN_USERNAME and ADMIN_PASSWORD
// are configured as Cloudflare secrets (Dashboard → Workers → Settings →
// Variables and Secrets) and no admin user exists yet, this creates the user
// with admin=1. The actual creation is delegated to the AdminDurableObject
// so that a distributed lock can serialize concurrent requests across worker
// instances.
//
// Why runtime and not build-time: Cloudflare worker secrets are only
// available at runtime - they are never injected into the Git integration
// build environment. Configuring them as Dashboard secrets keeps the
// plaintext password out of git and out of build logs.
//
// KV cache: subsequent requests within CACHE_TTL_SECONDS short-circuit the
// Durable Object call. Pass { force: true } to bypass the cache (useful
// after rotating ADMIN_USERNAME).

import type { Env } from '../types';

const CACHE_KEY = 'bootstrap:admin:done';
const CACHE_TTL_SECONDS = 24 * 60 * 60; // 24 hours

export interface BootstrapOptions {
  force?: boolean;
}

/**
 * Ensure an initial admin user exists. Idempotent and cheap on the hot path.
 *
 * - If ADMIN_USERNAME or ADMIN_PASSWORD is unset, logs once and returns.
 * - If a recent KV marker exists (and !force), returns.
 * - Otherwise the AdminDurableObject runs the actual check + create.
 */
export async function ensureBootstrapAdmin(env: Env, opts: BootstrapOptions = {}): Promise<void> {
  if (!env.ADMIN_USERNAME || !env.ADMIN_PASSWORD) {
    console.log('[bootstrap] Skipped: ADMIN_USERNAME or ADMIN_PASSWORD secret not configured');
    return;
  }

  if (!opts.force) {
    const cached = await env.CACHE.get(CACHE_KEY);
    if (cached) {
      return;
    }
  }

  try {
    const id = env.ADMIN.idFromName('global');
    const stub = env.ADMIN.get(id);
    const url = opts.force ? 'http://internal/bootstrap?force=1' : 'http://internal/bootstrap';
    const response = await stub.fetch(url, { method: 'POST' });
    const body = await response.json().catch(() => ({})) as { ok?: boolean; action?: string; reason?: string; user_id?: string };

    if (response.ok && body.ok) {
      console.log(`[bootstrap] ${body.action}: ${body.reason ?? ''}${body.user_id ? ` user=${body.user_id}` : ''}`);
      await env.CACHE.put(CACHE_KEY, '1', { expirationTtl: CACHE_TTL_SECONDS });
    } else {
      console.warn(`[bootstrap] DO returned ${response.status}: action=${body.action} reason=${body.reason}`);
    }
  } catch (err) {
    console.error('[bootstrap] Failed to contact AdminDO:', err);
  }
}
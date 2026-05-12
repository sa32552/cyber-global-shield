// =============================================================================
// Cyber Global Shield — Supabase Browser Client
// =============================================================================
// This client is used in the browser (client components).
// It uses cookies for session management via @supabase/ssr.

import { createBrowserClient } from "@supabase/ssr";

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL ?? "";
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "";

export function createClient() {
  return createBrowserClient(supabaseUrl, supabaseAnonKey);
}

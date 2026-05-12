-- =============================================================================
-- Cyber Global Shield — Supabase Database Schema
-- =============================================================================
-- Run this SQL in the Supabase SQL Editor (https://supabase.com/dashboard/project/_/sql/new)
-- This creates the multi-tenant tables and RLS policies.
-- =============================================================================

-- ─── Organizations ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    tier TEXT NOT NULL DEFAULT 'free' CHECK (tier IN ('free', 'starter', 'business', 'enterprise')),
    max_users INTEGER NOT NULL DEFAULT 5,
    max_alerts_per_day INTEGER NOT NULL DEFAULT 1000,
    features JSONB NOT NULL DEFAULT '{
        "ml_detection": true,
        "soar_playbooks": false,
        "federated_learning": false,
        "quantum_modules": false,
        "threat_intel": false,
        "custom_dashboard": false
    }'::jsonb,
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ─── Profiles (extends auth.users) ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL DEFAULT '',
    avatar_url TEXT,
    role TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'soc_engineer', 'analyst', 'viewer')),
    permissions TEXT[] NOT NULL DEFAULT '{}',
    preferences JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ─── API Keys ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash TEXT UNIQUE NOT NULL,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT 'default',
    role TEXT NOT NULL DEFAULT 'analyst',
    permissions TEXT[] NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ─── Indexes ───────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_profiles_org_id ON public.profiles(org_id);
CREATE INDEX IF NOT EXISTS idx_profiles_role ON public.profiles(role);
CREATE INDEX IF NOT EXISTS idx_api_keys_org_id ON public.api_keys(org_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON public.api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_organizations_slug ON public.organizations(slug);

-- ─── Triggers ──────────────────────────────────────────────────────────────

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'set_organizations_updated_at') THEN
        CREATE TRIGGER set_organizations_updated_at
            BEFORE UPDATE ON public.organizations
            FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'set_profiles_updated_at') THEN
        CREATE TRIGGER set_profiles_updated_at
            BEFORE UPDATE ON public.profiles
            FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
    END IF;
END;
$$;

-- Auto-create profile when a new user signs up via Supabase Auth
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
    default_org_id UUID;
    org_name TEXT;
BEGIN
    -- Get or create default organization
    org_name := NEW.raw_user_meta_data ->> 'org_name';
    IF org_name IS NULL OR org_name = '' THEN
        org_name := 'Default Organization';
    END IF;

    -- Check if organization already exists by slug
    SELECT id INTO default_org_id FROM public.organizations
    WHERE slug = lower(regexp_replace(org_name, '[^a-zA-Z0-9]+', '-', 'g'));

    IF default_org_id IS NULL THEN
        INSERT INTO public.organizations (name, slug, tier)
        VALUES (
            org_name,
            lower(regexp_replace(org_name, '[^a-zA-Z0-9]+', '-', 'g')),
            'free'
        )
        RETURNING id INTO default_org_id;
    END IF;

    -- Create profile
    INSERT INTO public.profiles (id, org_id, full_name, role, permissions)
    VALUES (
        NEW.id,
        default_org_id,
        COALESCE(NEW.raw_user_meta_data ->> 'full_name', ''),
        COALESCE(NEW.raw_user_meta_data ->> 'role', 'analyst'),
        CASE
            WHEN COALESCE(NEW.raw_user_meta_data ->> 'role', 'analyst') = 'admin'
            THEN ARRAY['*']
            ELSE ARRAY['alerts:read', 'dashboard:read', 'soar:execute']
        END
    );

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Drop the trigger if it exists, then create it
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ─── Row Level Security (RLS) ──────────────────────────────────────────────

-- Enable RLS on all tables
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;

-- ─── Organizations RLS Policies ────────────────────────────────────────────

-- Users can view their own organization
CREATE POLICY "users_view_own_org" ON public.organizations
    FOR SELECT
    USING (
        id IN (
            SELECT org_id FROM public.profiles WHERE id = auth.uid()
        )
    );

-- Only admin users can update their organization
CREATE POLICY "admins_update_own_org" ON public.organizations
    FOR UPDATE
    USING (
        id IN (
            SELECT org_id FROM public.profiles
            WHERE id = auth.uid() AND role = 'admin'
        )
    )
    WITH CHECK (
        id IN (
            SELECT org_id FROM public.profiles
            WHERE id = auth.uid() AND role = 'admin'
        )
    );

-- ─── Profiles RLS Policies ─────────────────────────────────────────────────

-- Users can view profiles in their own organization
CREATE POLICY "users_view_org_profiles" ON public.profiles
    FOR SELECT
    USING (
        org_id IN (
            SELECT org_id FROM public.profiles WHERE id = auth.uid()
        )
    );

-- Users can update their own profile
CREATE POLICY "users_update_own_profile" ON public.profiles
    FOR UPDATE
    USING (id = auth.uid())
    WITH CHECK (id = auth.uid());

-- Admin users can update any profile in their organization
CREATE POLICY "admins_update_org_profiles" ON public.profiles
    FOR UPDATE
    USING (
        org_id IN (
            SELECT org_id FROM public.profiles
            WHERE id = auth.uid() AND role = 'admin'
        )
    );

-- ─── API Keys RLS Policies ─────────────────────────────────────────────────

-- Users can view API keys in their organization
CREATE POLICY "users_view_org_api_keys" ON public.api_keys
    FOR SELECT
    USING (
        org_id IN (
            SELECT org_id FROM public.profiles WHERE id = auth.uid()
        )
    );

-- Users can create API keys for their organization
CREATE POLICY "users_create_org_api_keys" ON public.api_keys
    FOR INSERT
    WITH CHECK (
        org_id IN (
            SELECT org_id FROM public.profiles WHERE id = auth.uid()
        )
    );

-- Users can delete their own API keys
CREATE POLICY "users_delete_own_api_keys" ON public.api_keys
    FOR DELETE
    USING (user_id = auth.uid());

-- ─── Seed Data ─────────────────────────────────────────────────────────────

-- Insert default organization for development
INSERT INTO public.organizations (name, slug, tier, max_users)
VALUES ('Cyber Global Shield', 'cyber-global-shield', 'enterprise', 1000)
ON CONFLICT (slug) DO NOTHING;

INSERT INTO public.organizations (name, slug, tier, max_users)
VALUES ('Demo PME', 'demo-pme', 'free', 5)
ON CONFLICT (slug) DO NOTHING;

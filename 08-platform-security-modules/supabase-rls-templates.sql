-- ==============================================================================
-- Kaizo DevSec Framework - Production Supabase RLS & Database Hardening Template
-- ==============================================================================

-- 1. Enable RLS on all public tables
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- 2. Revoke public execution of dangerous functions
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM public, anon;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO authenticated;

-- ------------------------------------------------------------------------------
-- PROFILES POLICIES
-- ------------------------------------------------------------------------------
CREATE POLICY "Public profiles are viewable by everyone" 
ON public.profiles FOR SELECT 
USING (true);

CREATE POLICY "Users can insert their own profile" 
ON public.profiles FOR INSERT 
TO authenticated 
WITH CHECK ((SELECT auth.uid()) = id);

CREATE POLICY "Users can update own profile" 
ON public.profiles FOR UPDATE 
TO authenticated 
USING ((SELECT auth.uid()) = id)
WITH CHECK ((SELECT auth.uid()) = id);

-- ------------------------------------------------------------------------------
-- TEAM MEMBERS & TENANCY POLICIES
-- ------------------------------------------------------------------------------
CREATE POLICY "Team members can view their teams"
ON public.teams FOR SELECT
TO authenticated
USING (
  id IN (
    SELECT team_id FROM public.team_members 
    WHERE user_id = (SELECT auth.uid())
  )
);

CREATE POLICY "Team admins can manage team"
ON public.teams FOR ALL
TO authenticated
USING (
  id IN (
    SELECT team_id FROM public.team_members 
    WHERE user_id = (SELECT auth.uid()) AND role IN ('admin', 'owner')
  )
);

-- ------------------------------------------------------------------------------
-- PROJECTS & DATA ACCESS POLICIES
-- ------------------------------------------------------------------------------
CREATE POLICY "Team members can view team projects"
ON public.projects FOR SELECT
TO authenticated
USING (
  team_id IN (
    SELECT team_id FROM public.team_members 
    WHERE user_id = (SELECT auth.uid())
  )
);

CREATE POLICY "Only team editors and admins can insert projects"
ON public.projects FOR INSERT
TO authenticated
WITH CHECK (
  team_id IN (
    SELECT team_id FROM public.team_members 
    WHERE user_id = (SELECT auth.uid()) AND role IN ('admin', 'owner', 'editor')
  )
);

-- ------------------------------------------------------------------------------
-- AUDIT LOG (APPEND-ONLY, NO UPDATE / DELETE ALLOWED)
-- ------------------------------------------------------------------------------
CREATE POLICY "Admins can view audit logs"
ON public.audit_logs FOR SELECT
TO authenticated
USING (
  (SELECT (auth.jwt() -> 'app_metadata' ->> 'role')) = 'admin'
);

-- Disable UPDATE & DELETE for everyone (Immutable logs)
CREATE POLICY "No one can update audit logs"
ON public.audit_logs FOR UPDATE
USING (false);

CREATE POLICY "No one can delete audit logs"
ON public.audit_logs FOR DELETE
USING (false);

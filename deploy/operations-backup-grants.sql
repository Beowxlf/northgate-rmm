-- Run as deployment DBA after the operations migration. No write grant.
GRANT SELECT ON TABLE public.ops_schema, public.ops_records, public.ops_versions,
  public.ops_scopes, public.ops_events, public.ops_enrollments,
  public.ops_requests, public.ops_alert_sources, public.ops_artifacts,
  public.ops_chunks TO rmm_backup;

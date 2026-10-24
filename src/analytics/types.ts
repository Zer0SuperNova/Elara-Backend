export type AnalyticsTable = 
  | 'auth_events' 
  | 'app_events' 
  | 'api_requests' 
  | 'client_diagnostics' 
  | 'server_issues';

export type AuthEventType =
  | 'login_success'
  | 'login_failed'
  | 'session_resumed'
  | 'resume_failed';

export type AuthOutcome = 'success' | 'failure';

export type AuthReason =
  | ''
  | 'bad_password'
  | 'unknown_user'
  | 'banned_device'
  | 'hwid_lock'
  | 'inactive_account'
  | 'no_password_hash'
  | 'build_error'
  | (string & {});

export interface AuthEventInput {
  event_type: AuthEventType;
  outcome: AuthOutcome;
  reason?: AuthReason;
  user_id?: string;
  username?: string;
  psk_type?: string;
  ip?: string;
  country?: string;
  hwid?: string;
  build_id?: string;
  loader_id?: string;
  session_id?: string;
  meta?: Record<string, unknown>;
}

export interface AppEventInput {
  category: 'license' | 'build' | 'product' | 'security' | 'model' | (string & {});
  action: string;
  user_id?: string;
  target_id?: string;
  psk_type?: string;
  ip?: string;
  country?: string;
  build_id?: string;
  loader_id?: string;
  meta?: Record<string, unknown>;
}

export interface ApiRequestInput {
  method: string;
  route: string;
  status: number;
  duration_ms: number;
  user_id?: string;
  psk_type?: string;
  ip?: string;
  country?: string;
  build_id?: string;
  loader_id?: string;
}

// Client-side diagnostic
export interface ClientDiagnosticsInput {
  event_type: string;
  severity?: string;
  message?: string;
  error_code?: string;
  user_id?: string;
  username?: string;
  session_id?: string;
  psk_type?: string;
  build_id?: string;
  loader_id?: string;
  ip?: string;
  country?: string;
  meta?: Record<string, unknown>;
}


// server side issues
export interface ServerIssueInput {
  method?: string;
  route: string;
  status: number;
  error_code?: string;
  message?: string;
  user_id?: string;
  psk_type?: string;
  ip?: string;

  request_body?: unknown;
  response_body?: unknown;
}
create table if not exists sessions (
  id varchar(64) primary key,
  user_id varchar(128) not null,
  client_type varchar(64) not null,
  session_label varchar(255) not null default '',
  created_at timestamptz not null
);

create table if not exists projects (
  id varchar(64) primary key,
  name varchar(255) not null,
  tenant_id varchar(128),
  local_path text,
  remote_path text,
  created_at timestamptz not null
);

create table if not exists execution_requests (
  id varchar(64) primary key,
  session_id varchar(64) not null,
  tool_name varchar(128) not null,
  payload_json text not null,
  mode_at_submit varchar(64) not null,
  status varchar(64) not null,
  summary text not null,
  created_at timestamptz not null
);

create table if not exists execution_results (
  id varchar(64) primary key,
  request_id varchar(64) not null,
  tool_name varchar(128) not null,
  status varchar(64) not null,
  summary text not null,
  output_text text not null,
  created_at timestamptz not null
);

create table if not exists audit_events (
  id varchar(64) primary key,
  actor_id varchar(128) not null,
  action varchar(128) not null,
  entity_type varchar(128) not null,
  entity_id varchar(64) not null,
  summary text not null,
  created_at timestamptz not null
);

create table if not exists api_tokens (
  id varchar(64) primary key,
  user_id varchar(128) not null,
  token_label varchar(128) not null,
  token_hash varchar(255) not null unique,
  created_at timestamptz not null
);

create table if not exists approvals (
  id varchar(64) primary key,
  session_id varchar(64) not null,
  actor_id varchar(128) not null,
  tool_name varchar(128) not null,
  mode_at_submit varchar(64) not null,
  status varchar(64) not null,
  summary text not null,
  payload_json text not null,
  decision_notes text not null default '',
  surge_task_id varchar(128),
  execution_result_id varchar(64),
  created_at timestamptz not null,
  updated_at timestamptz not null
);

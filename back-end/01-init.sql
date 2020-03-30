create database use_easy_authn_passwordless encoding 'UTF-8';

\c use_easy_authn_passwordless;

create table accounts (
  id serial primary key,
  username text not null unique,
  session_id text not null unique,
  easyauthn_user_id text not null unique,
  login_token text not null unique,
  create_token text not null unique,
  is_ready boolean not null default false,
  created_at timestamptz not null default now()
);
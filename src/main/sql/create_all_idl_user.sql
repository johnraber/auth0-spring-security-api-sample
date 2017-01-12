--CREATE ROLE john LOGIN
--  NOSUPERUSER INHERIT CREATEDB CREATEROLE NOREPLICATION;
--GRANT rds_superuser TO john;

DROP SCHEMA idl CASCADE;
CREATE SCHEMA IF NOT EXISTS idl AUTHORIZATION postgres;

DROP SCHEMA idl_user CASCADE;
CREATE SCHEMA IF NOT EXISTS idl_user AUTHORIZATION postgres;

-- organization
CREATE TABLE idl_user.org
(
  id bigserial NOT NULL,
  name character varying(96) UNIQUE NOT NULL,
  -- ISO 3166 supporting 2 or 3 characters
  country_code character varying(3) NOT NULL,
  created_at timestamp without time zone default (now() at time zone 'utc'),
  updated_at timestamp without time zone default (now() at time zone 'utc'),
  CONSTRAINT org_pkey PRIMARY KEY (id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE idl_user.org
  OWNER TO postgres;


-- This is the table of users that are authenticated from 3rd party
-- Feel free to add more fields from Auth0 (JWT token) that are needed, note app specific not from Auth0
--   can be put into the app_user table
CREATE TABLE idl_user.auth0_user
(
  auth0_id character varying(96) NOT NULL,
  email character varying(96) NOT NULL,
  first_name character varying(40) DEFAULT NULL,
  last_name character varying(40) DEFAULT NULL,
  created_at timestamp without time zone default (now() at time zone 'utc'),
  updated_at timestamp without time zone default (now() at time zone 'utc'),
  CONSTRAINT auth0_user_pkey PRIMARY KEY (auth0_id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE idl_user.auth0_user
  OWNER TO postgres;



-- may want to revisit the cascading delete after more understanding of user mgmt if auth0 were to be swapped out
CREATE TABLE idl_user.user
(
  id bigserial NOT NULL,
  org_id bigint,
  -- email could be used for inviting users before they sign up or just user provided
  email character varying(96) DEFAULT NULL,
  -- having a single auth0 id here does not support linked user accounts, it does however support the notion that
  -- different authentication mechanisms (auth0 username/password, google-oauth, ..) by auth0 can have different roles and permissions
  auth0_id character varying(96)  DEFAULT NULL, -- allowing null to support invite flow where only email is known before authentication
  created_at timestamp without time zone default (now() at time zone 'utc'),
  updated_at timestamp without time zone default (now() at time zone 'utc'),
  CONSTRAINT user_pkey PRIMARY KEY (id),
  CONSTRAINT user_auth0_id_key UNIQUE (auth0_id),
  CONSTRAINT user_org_id_fkey FOREIGN KEY (org_id)
    REFERENCES idl_user.org (id) MATCH SIMPLE,
  CONSTRAINT user_auth0_id_fkey FOREIGN KEY (auth0_id)
    REFERENCES idl_user.auth0_user (auth0_id) MATCH SIMPLE
    ON UPDATE CASCADE ON DELETE CASCADE
)
WITH (
  OIDS=FALSE
);
ALTER TABLE idl_user.user
  OWNER TO postgres;


-- Support possibility of a single idl user to multiple auth0 users if not linking accounts without
-- exluding support for a user with multiple id_user entries if driven off multiple auth0_user ids
-- with no linking of accounts
-- CREATE TABLE idl_user.user_auth0_user
-- (
--   id bigserial NOT NULL,
--   user_id bigint NOT NULL,
--   auth0_id character varying(96) NOT NULL,
--   created_at timestamp without time zone default (now() at time zone 'utc'),
--   updated_at timestamp without time zone default (now() at time zone 'utc'),
--   CONSTRAINT user_auth0_user_pkey PRIMARY KEY (id),
--   CONSTRAINT user_auth0_user_user_id_fkey FOREIGN KEY (user_id)
--     REFERENCES idl_user.user (id) MATCH SIMPLE
--     ON UPDATE CASCADE ON DELETE CASCADE,
--   CONSTRAINT user_auth0_user_auth0_id_fkey FOREIGN KEY (auth0_id)
--     REFERENCES idl_user.auth0_user (auth0_id) MATCH SIMPLE
--     ON UPDATE CASCADE ON DELETE CASCADE,
--   CONSTRAINT user_auth0_user_user_id_auth0_id_key UNIQUE (user_id, auth0_id)
-- )
-- WITH (
--   OIDS=FALSE
-- );
-- ALTER TABLE idl_user.user_auth0_user
--   OWNER TO postgres;


-- A service platform or application
CREATE TABLE idl.service
(
  id bigserial NOT NULL,
  name character varying(96) NOT NULL,
  third_party_auth_app_id character varying(96) NOT NULL,
  base_url character varying(96),
  version character varying(96) NOT NULL DEFAULT '1.0',
  description character varying(96),
  created_at timestamp without time zone default (now() at time zone 'utc'),
  updated_at timestamp without time zone default (now() at time zone 'utc'),
  CONSTRAINT service_id_pkey PRIMARY KEY (id),
  CONSTRAINT service_name_version_key UNIQUE (name, version)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE idl_user.org
  OWNER TO postgres;

INSERT INTO idl.service VALUES (1, 'prototype_service', 'bW4hAsU35OkxECU2voRssgZ5GWQIvVhp', '/api/', 'demo');

-- This is the table to specify what roles and permissions each user has for each specific application or
--   service platform where the platform is denoted by service_id.  The service
--   uses the unique client that is registered with the 3rd party authentication provider.
CREATE TABLE idl.service_registry
(
  id bigserial NOT NULL,
  user_id bigint NOT NULL,
  service_id bigint NOT NULL,
  roles jsonb,
  permissions jsonb,
  -- 3rd party client id is used by the service/platform/application when authenticating users
  third_party_client_id character varying(96) NOT NULL,
  created_at timestamp without time zone default (now() at time zone 'utc'),
  updated_at timestamp without time zone default (now() at time zone 'utc'),
  CONSTRAINT service_registry_pkey PRIMARY KEY (id),
  CONSTRAINT service_registry_user_id_fkey FOREIGN KEY (user_id)
    REFERENCES idl_user.user (id) MATCH SIMPLE,
  CONSTRAINT service_registry_service_id_fkey FOREIGN KEY (service_id)
    REFERENCES idl.service (id) MATCH SIMPLE,
  CONSTRAINT service_registry_user_id_service_id_key UNIQUE (user_id, service_id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE idl.service_registry
  OWNER TO postgres;

CREATE INDEX service_registry_permissions_idx
  ON idl.service_registry
  USING gin
  (permissions);

CREATE INDEX service_registry_roles_idx
  ON idl.service_registry
  USING gin
  (roles);


DROP SCHEMA idl_portal CASCADE;
CREATE SCHEMA idl_portal AUTHORIZATION postgres;

CREATE TABLE idl_portal.portal_ap
(
  id bigserial NOT NULL,
  product_id bigserial NOT NULL,
  redmac character varying(96) NOT NULL,
  serial_num character varying(96)  NOT NULL,
  created_at timestamp without time zone default (now() at time zone 'utc'),
  updated_at timestamp without time zone default (now() at time zone 'utc'),
  CONSTRAINT portal_ap_pkey PRIMARY KEY (id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE idl_portal.portal_ap
  OWNER TO postgres;


-- a portal network is a collection of portal aps and each network must have a unique name per owner
CREATE TABLE idl_portal.portal_network
(
  id bigserial NOT NULL,
  net_name character varying(96) NOT NULL,
  owner bigint NOT NULL,
  created_at timestamp without time zone default (now() at time zone 'utc'),
  updated_at timestamp without time zone default (now() at time zone 'utc'),
  CONSTRAINT portal_network_pkey PRIMARY KEY (id),
  CONSTRAINT owner_fkey FOREIGN KEY (owner)
    REFERENCES idl_user.user (id) MATCH SIMPLE,
  CONSTRAINT owner_name_key UNIQUE (owner, net_name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE idl_portal.portal_network
  OWNER TO postgres;


CREATE TABLE idl_portal.portal_network_app
(
  id bigserial NOT NULL,
  portal_network_id bigint NOT NULL,
  portal_ap_id bigint NOT NULL,
  created_at timestamp without time zone default (now() at time zone 'utc'),
  updated_at timestamp without time zone default (now() at time zone 'utc'),
  CONSTRAINT portal_network_app_pkey PRIMARY KEY (id),
  CONSTRAINT portal_network_id_fkey FOREIGN KEY (portal_network_id)
    REFERENCES idl_portal.portal_network (id) MATCH SIMPLE
    ON UPDATE CASCADE ON DELETE CASCADE,
   CONSTRAINT portal_ap_id_fkey FOREIGN KEY (portal_ap_id)
    REFERENCES idl_portal.portal_ap (id) MATCH SIMPLE
    ON UPDATE CASCADE ON DELETE CASCADE
)
WITH (
  OIDS=FALSE
);
ALTER TABLE idl_portal.portal_network_app
  OWNER TO postgres;





-- this table captures a user and their role for a portal network and the
-- time in which the user has this role
CREATE TABLE idl_portal.portal_network_registry
(
  id bigserial NOT NULL,
  portal_network_id bigint NOT NULL,
  user_id bigint NOT NULL,
  portal_network_role character varying(96) NOT NULL,
  start_time timestamp without time zone default (now() at time zone 'utc'),
  stop_time timestamp without time zone default (now() at time zone 'utc'),
  created_at timestamp without time zone default (now() at time zone 'utc'),
  updated_at timestamp without time zone default (now() at time zone 'utc'),
  CONSTRAINT portal_network_registry_pkey PRIMARY KEY (id),
  CONSTRAINT portal_network_id_fkey FOREIGN KEY (portal_network_id)
    REFERENCES idl_portal.portal_network (id) MATCH SIMPLE
    ON UPDATE CASCADE ON DELETE CASCADE,
   CONSTRAINT user_id_fkey FOREIGN KEY (user_id)
    REFERENCES idl_user.user (id) MATCH SIMPLE
--    ON UPDATE CASCADE ON DELETE CASCADE
)
WITH (
  OIDS=FALSE
);
ALTER TABLE idl_portal.portal_network_registry
  OWNER TO postgres;

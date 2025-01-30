DROP TABLE IF EXISTS subject;
CREATE TABLE subject (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE
);

DROP TABLE IF EXISTS file_info;
CREATE TABLE file_info (
    file_key BYTEA PRIMARY KEY,
    content BYTEA NOT NULL,
    alg TEXT NOT NULL,
    sim_key BYTEA NOT NULL
);

DROP TABLE IF EXISTS document;
CREATE TABLE document (
    document_handle INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_name TEXT NOT NULL,
    create_date DATE NOT NULL,
    creator_id INTEGER NOT NULL,
    org_id INTEGER NOT NULL,
    deleter_id INTEGER,
    file_handle BYTEA,
    FOREIGN KEY (creator_id) REFERENCES organization_member(subject_id),
    FOREIGN KEY (org_id) REFERENCES organization_member(org_id),
    FOREIGN KEY (file_handle) REFERENCES file_info(file_key)
);

DROP TABLE IF EXISTS [role];
CREATE TABLE role (
    org_id INTEGER NOT NULL,
    role_name TEXT NOT NULL,
    PRIMARY KEY (org_id, role_name),
    FOREIGN KEY (org_id) REFERENCES organization(id)
);

DROP TABLE IF EXISTS organization;
CREATE TABLE organization (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_name TEXT
);

DROP TABLE IF EXISTS organization_member;
CREATE TABLE organization_member (
    subject_id INTEGER NOT NULL,
    org_id INTEGER NOT NULL,
    pub_key TEXT NOT NULL,
    subject_status TEXT NOT NULL,
    PRIMARY KEY (subject_id, org_id),
    FOREIGN KEY (subject_id) REFERENCES subject(id),
    FOREIGN KEY (org_id) REFERENCES role(id)
);

DROP TABLE IF EXISTS acl;
CREATE TABLE acl (
    perm_name TEXT PRIMARY KEY NOT NULL
);

DROP TABLE IF EXISTS member_roles;
CREATE TABLE member_roles (
    subject_id INTEGER NOT NULL,
    org_id INTEGER NOT NULL,
    role_name TEXT NOT NULL,
    PRIMARY KEY (subject_id, org_id, role_name),
    FOREIGN KEY (subject_id) REFERENCES subject(id),
    FOREIGN KEY (org_id) REFERENCES role(org_id),
    FOREIGN KEY (role_name) REFERENCES role(role_name)
);

DROP TABLE IF EXISTS role_permissions;
CREATE TABLE role_permissions (
    org_id INTEGER NOT NULL,
    role_name TEXT NOT NULL,
    perm_name TEXT NOT NULL,
    PRIMARY KEY (org_id, role_name, perm_name),
    FOREIGN KEY (org_id) REFERENCES role(org_id),
    FOREIGN KEY (role_name) REFERENCES role(role_name),
    FOREIGN KEY (perm_name) REFERENCES acl(perm_name)
);

DROP TABLE IF EXISTS [session];
CREATE TABLE session (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    subject_id INTEGER NOT NULL,
    last_interaction TIMESTAMP NOT NULL,
    number_of_interactions INTEGER DEFAULT 0 NOT NULL,
    FOREIGN KEY (org_id) REFERENCES organization(id),
    FOREIGN KEY (subject_id) REFERENCES subject(id)
);

DROP TABLE IF EXISTS session_keys;
CREATE TABLE session_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    session_key TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES session(id)
);

CREATE TABLE nonce (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nonce TEXT KEY NOT NULL,
    session_id INTEGER NOT NULL,
    FOREIGN KEY (session_id) REFERENCES session(id)
);
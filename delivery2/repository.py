import document_acl
from flask import Flask, request, jsonify, json, send_file
import sqlite3
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import sys
from decrypt_command import decrypt_data, string_bytes, load_rep_privkey
from encrypt_command import encrypt_data, bytes_to_string, load_rep_pubkey
from cryptography.hazmat.primitives import serialization
from io import BytesIO
import os
from cryptography.exceptions import InvalidSignature
from signing import sign_data_coms, verify_signature_coms
import org_acl
import role_acl

app = Flask(__name__)
MASTER_KEY = b'\xb2\x96\xd0R\xa9=\xce\x83R\xd5\x8d\xc3\\\x940,rU\xee\x9c_+\x06\xd9\x9dq*l\x07\x1bJ\x13'
SESSION_LIFETIME = 6000
CHALLENGE_LIFETIME = 7
DATE_FORMAT = "%Y-%m-%d %H:%M:%S.%f"

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def populate_acl():
    acls = list(org_acl.org_acl)
    acls.extend(list(role_acl.role_acl))

    document_perms = list(document_acl.document_acl)

    conn = get_db_connection()
    
    for acl in acls:
        # Avoid repeating insertion
        acl_name = acl.name
        acl_exists = conn.execute("SELECT 1 FROM acl WHERE perm_name = ?", (acl_name,)).fetchone()
        if acl_exists:
            continue

        conn.execute("INSERT INTO acl (perm_name) VALUES (?)",(acl_name,))
        conn.commit()

    for doc_acl in document_perms:
        # Avoid repeating insertion
        acl_name = doc_acl.name
        acl_exists = conn.execute("SELECT 1 FROM document_acl WHERE perm_name = ?", (acl_name,)).fetchone()
        if acl_exists:
            continue

        conn.execute("INSERT INTO document_acl (perm_name) VALUES (?)",(acl_name,))
        conn.commit()

    conn.close()

def verify_password():
    password = input("Enter password: ")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode())
    d = digest.finalize()

    if d == MASTER_KEY:
        print("Password verified successfully.")
        return 
    else:
        print("Invalid password. Exiting.")
        sys.exit(-1)     

def check_session_lifetime(conn, org_id, sub_id):
    last_interaction = conn.execute("SELECT last_interaction FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()

    if not last_interaction:
        conn.close()
        return False
    
    time_object = datetime.datetime.strptime(last_interaction[0], DATE_FORMAT)
    time = int(time_object.timestamp()) 
    
    if (datetime.datetime.timestamp(datetime.datetime.now()) - time) > SESSION_LIFETIME:
        session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
        conn.execute("DELETE FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id))
        conn.commit()
        conn.execute("DELETE FROM session_keys WHERE session_id = ?", (session_id,))
        conn.commit()
        return False   

    conn.execute("UPDATE session SET last_interaction = ? WHERE org_id = ? AND subject_id = ?", (datetime.datetime.now(), org_id, sub_id))
    return True    
    
def verify_nonce(conn, org_id, sub_id, nonce):
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    verify_nonce = conn.execute("SELECT nonce FROM nonce WHERE session_id = ?", (session_id,)).fetchone()

    if not verify_nonce:
        conn.execute("UPDATE nonce SET nonce = ? WHERE session_id = ?", (nonce, session_id))
        conn.commit()

    return verify_nonce is None

def verify_seq_num(conn, org_id, sub_id, seq_num):
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    verify_seq_num = conn.execute("SELECT number_of_interactions FROM session WHERE id = ?", (session_id,)).fetchone()

    if verify_seq_num[0] > seq_num:
        return False
    else:
        conn.execute("UPDATE session SET number_of_interactions = ? WHERE id = ?", (seq_num + 1, session_id))
        conn.commit()
        return True
    
def verify_signature(conn, org_id, sub_id, signature, key: str):
    auth_key = conn.execute("SELECT auth_key FROM session_keys WHERE session_id = (SELECT id FROM session WHERE org_id = ? AND subject_id = ?)", (org_id, sub_id)).fetchone()
    public_key = serialization.load_pem_public_key(key.encode())

    if not auth_key:
        return False

    try:
        public_key.verify(
            bytes.fromhex(signature),
            auth_key[0],
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature as e:
        conn.close()
        return False
    
def sign_data(data):
    priv_key = load_rep_privkey()
    rep_private_key = serialization.load_pem_private_key(priv_key.encode(), password=None)
    signature = rep_private_key.sign(json.dumps(data).encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    return signature.hex()

@app.route("/organization/list", methods=["GET"])
def list_organizations():
    conn = get_db_connection()
    try:
        orgs = conn.execute("SELECT id, org_name FROM organization").fetchall()
        conn.close()

        organizations = [{"id": org["id"], "org_name": org["org_name"]} for org in orgs]

        result = {
            "organizations": organizations
        }

        return jsonify(result), 200
    
    except Exception as e:
        conn.close()
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


@app.route("/session/list", methods=['GET'])
def session_list():
    conn = get_db_connection()
    sessions = conn.execute("SELECT * FROM session").fetchall()
    conn.close()

    sessions_list = [{"id": session["id"], "organization": session["organization"], "subject": session["subject"]}
                     for session in sessions]
    return jsonify(sessions_list), 200

@app.route("/organization", methods=['POST'])
def org_create():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json())
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)
    org_name = data.get("organization")
    username = data.get("username")
    name = data.get("name")
    email = data.get("email")
    public_key = data.get("public_key")

    if not all([org_name, username, name, email, public_key]):
        return jsonify({"error": "Missing required fields"}), 400

    # Check if the organization already exists
    org_exists = conn.execute("SELECT 1 FROM organization WHERE org_name = ?", (org_name,)).fetchone()
    if org_exists:
        conn.close()
        response = {"error": "Organization already exists"}
        signatute = sign_data(response)
        return jsonify({"response": response, "signature": signatute}), 400
    
    # verify if the creator exists
    creator_exists = conn.execute("SELECT 1 FROM subject WHERE username = ?", (username,)).fetchone()

    if not creator_exists:
        # Insert subject (creator) into the database
        conn.execute("INSERT INTO subject (username, full_name, email) VALUES (?, ?, ?)",
                    (username, name, email))
        conn.commit()

    # Get the subject ID of the creator
    creator_id = conn.execute("SELECT id FROM subject WHERE username = ?", (username,)).fetchone()[0]

    conn.execute("INSERT INTO organization (org_name) VALUES (?)", (org_name,))
    conn.commit()

    org_id = conn.execute("SELECT id FROM organization WHERE org_name = ?", (org_name,)).fetchone()[0]

    # Add the creator as a member of the organization with a "manager" role
    conn.execute("INSERT INTO organization_member (subject_id, org_id, pub_key, subject_status) VALUES (?, ?, ?, ?)",
                 (creator_id, org_id, public_key, "active"))
    conn.execute("INSERT INTO role (org_id, role_name) VALUES (?, ?)", (org_id, "manager"))
    conn.execute("INSERT INTO member_roles (subject_id, org_id, role_name) VALUES (?, ?, ?)",
                 (creator_id, org_id, "manager"))
    conn.commit()

    all_acl = conn.execute("SELECT perm_name FROM acl").fetchall()

    

    for acl in all_acl:
        acl_name = acl[0]
        print("ACL:", acl_name)
        conn.execute("INSERT INTO role_permissions (org_id, role_name, perm_name) VALUES (?, ?, ?)", (org_id, "manager", acl_name))
        conn.commit()

    conn.close()

    response = {"message": "Organization created successfully"}
    signature = sign_data(response)

    return jsonify({"response": response, "signature": signature}), 201

@app.route("/document", methods=['DELETE'])
def delete_document():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data["org_id"]
    sub_id = data["sub_id"] 
    doc_name = data["document"]
    signature = data["signature"]

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400
    
    # verify if the role has the permission DOC_DELETE
    role = conn.execute("SELECT role_name FROM session_role WHERE subject_id = ? AND org_id = ?;", (sub_id, org_id)).fetchone()

    # fetch document id
    doc_id = conn.execute("SELECT document_handle FROM document WHERE doc_name = ? AND org_id = ?", (doc_name, org_id,)).fetchone()

    if not doc_id:
        conn.close()
        return jsonify(sign_data_coms({"error": "Document does not exist"}, load_rep_privkey())), 404
    
    doc_id = doc_id[0]
    perms = []
    cursor = conn.cursor()

    if role:
        cursor.execute("SELECT perm_name FROM document_role_permissions WHERE org_id = ? AND role_name = ? AND doc_id = ?", (org_id, role[0], doc_id,))
        perms.extend([row[0] for row in cursor.fetchall()])

    else:
        conn.close()
        return jsonify(sign_data_coms({"error": "No valid role."}, load_rep_privkey())), 403

    if "DOC_DELETE" not in perms:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid permission."}, load_rep_privkey())), 403

    file_handle = conn.execute("SELECT file_handle FROM document WHERE doc_name = ? AND org_id = ?", (doc_name, org_id,)).fetchone()[0]
    if not file_handle:
        conn.close()
        return jsonify(sign_data_coms({"error": "There is no document with the given file_handle."}, load_rep_privkey())), 400
        

    file_tuple = conn.execute("SELECT alg, sim_key FROM file_info WHERE file_key = ?", (file_handle,)).fetchone()

    #make file_handle null
    conn.execute("UPDATE document SET file_handle = NULL WHERE doc_name = ? AND org_id = ?", (doc_name, org_id,))
    conn.commit()

    conn.execute("UPDATE document SET deleter_id = ? WHERE doc_name = ? AND org_id = ?", (sub_id, doc_name, org_id,))
    conn.commit()

    conn.close()

    result = {
        "file_handle": file_handle,
        "alg": file_tuple["alg"],
        "key": file_tuple["sim_key"]
    }

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    data_str_signed = sign_data_coms(data_str, load_rep_privkey())
    
    return data_str_signed, 200

@app.route("/requestChallenge", methods=["POST"])
def request_challenge():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json())
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)
    username = data["username"]
    org_id = data["org_id"]
    user_pub_key = data["pub_key"]
    user_pub_key = bytes.fromhex(user_pub_key).decode()

    sub_id = conn.execute("SELECT id FROM subject WHERE username = ?", (username,)).fetchone()[0]
    if not sub_id:
        conn.close()
        return jsonify({"error": "Subject not found"}), 404
    
    # verify if the subject is suspended
    subject_status = conn.execute("SELECT subject_status FROM organization_member WHERE subject_id = ? AND org_id = ?", (sub_id, org_id)).fetchone()[0]

    if subject_status == "suspended":
        conn.close()
        return jsonify({"error": "Subject is suspended"}), 403

    pub_key = conn.execute("SELECT pub_key FROM organization_member WHERE subject_id = ? AND org_id = ?", (sub_id, org_id)).fetchone()[0]

    if pub_key != user_pub_key:
        conn.close()
        return jsonify({"error": "Invalid credentials or Invalid user"}), 401
    
    # verify if the challenge is still valid
    verify_challenge = conn.execute("SELECT challenge FROM challenge WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()
    verify_timestamp = conn.execute("SELECT last_interaction FROM challenge WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()

    if not verify_challenge:
        challenge = os.urandom(32)
        last_interaction = datetime.datetime.now() 

        conn.execute("INSERT INTO challenge (org_id, subject_id, challenge, last_interaction) VALUES (?, ?, ?, ?)", (org_id, sub_id, challenge, last_interaction))
        conn.commit()

    else:
        time = datetime.datetime.timestamp(datetime.datetime.now())
        time_object = datetime.datetime.strptime(verify_timestamp[0], DATE_FORMAT)
        last_time = int(time_object.timestamp()) 

        if (time - last_time) > CHALLENGE_LIFETIME:
            challenge = os.urandom(32)
            last_interaction = datetime.datetime.now() 

            conn.execute("UPDATE challenge SET challenge = ?, last_interaction = ? WHERE org_id = ? AND subject_id = ?", (challenge, last_interaction, org_id, sub_id))
            conn.commit()

        else:
            challenge = verify_challenge[0]

    conn.close()

    #encrypt data
    data_encrypted = encrypt_data(json.dumps({"challenge": challenge.hex()}), pub_key)
    data_str = bytes_to_string(data_encrypted)
    
    return data_str, 200

@app.route("/session", methods=['POST'])
def create_session():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json())
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)
    org_id = data["org_id"]
    username = data["username"]
    session_key = data["session_pub_key"]
    user_challenge_encrypted = data["challenge"]

    user_challenge_bytes = string_bytes(user_challenge_encrypted)
    user_challenge = decrypt_data(user_challenge_bytes, load_rep_privkey())

    if not all([org_id, username, session_key]):
        conn.close()
        return jsonify({"error": "Missing required fields"}), 400

    sub_id = conn.execute("SELECT id FROM subject WHERE username = ?", (username,)).fetchone()[0]
    if not sub_id:
        conn.close()
        return jsonify({"error": "Invalid credentials or Invalid user"}), 404

    challenge, timestamp = conn.execute("SELECT challenge, last_interaction FROM challenge WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()

    if not challenge:
        conn.close()
        return jsonify({"error": "Denied"}), 401
    
    time = datetime.datetime.timestamp(datetime.datetime.now())
    time_object = datetime.datetime.strptime(timestamp, DATE_FORMAT)
    last_time = int(time_object.timestamp())

    if (time - last_time) > CHALLENGE_LIFETIME:
        conn.close()
        return jsonify({"error": "Authentication failed"}), 401

    if challenge.hex() != user_challenge:
        conn.close()
        return jsonify({"error": "Authentication failed"}), 401
    
    # generate auth key for session and sign it
    auth_key = os.urandom(32)

    priv_key = load_rep_privkey()
    rep_private_key = serialization.load_pem_private_key(priv_key.encode(), password=None)
    signature = rep_private_key.sign(auth_key, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    # check if organization exists
    org = conn.execute("SELECT * FROM organization WHERE id = ?", (org_id,)).fetchone()[0]
    if not org:
        conn.close()
        return jsonify({"error": "Organization not found"}), 404
    
    last_interaction = datetime.datetime.now()  

    # verify if the session already exists
    verify_session = conn.execute("SELECT 1 FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()

    if verify_session:
        conn.execute("UPDATE session SET last_interaction = ?, number_of_interactions = ? WHERE org_id = ? AND subject_id = ?", (last_interaction, 0, org_id, sub_id))
        conn.commit()

    else:
        conn.execute("INSERT INTO session (org_id, subject_id, last_interaction, number_of_interactions) VALUES (?, ?, ?, ?)", (org_id, sub_id, last_interaction, 0))
        conn.commit()

    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]

    # verify if the sesion already has a auth_key
    verify_auth_key = conn.execute("SELECT auth_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()

    if verify_auth_key:
        conn.execute("UPDATE session_keys SET auth_key = ?, session_key = ? WHERE session_id = ?", (auth_key, session_key, session_id))
        conn.commit()
    
    else:
        conn.execute("INSERT INTO session_keys (session_id, session_key, auth_key) VALUES (?, ?, ?)", (session_id, session_key, auth_key))
        conn.commit()

    conn.close()

    response = {
        "sub_id": sub_id,
        "last_interaction": last_interaction,
        "signature": signature.hex()
    }

    #return encrypted data
    data_encrypted = encrypt_data(json.dumps(response), session_key)
    data_str = bytes_to_string(data_encrypted)

    return data_str, 200

@app.route("/subject", methods=['POST'])
def add_subject():
    conn = get_db_connection()

    #decrypted data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)
    org_id = data["org_id"] 
    sub_id = data["sub_id"]
    username = data["username"]
    name = data["name"]
    email = data["email"]
    pub_key = data["public_key"]
    status = "active"
    signature = data["signature"]

    pub_key_rep = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key_rep)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not all([org_id, username, name, email, pub_key]):
        return jsonify(sign_data_coms({"error": "Missing required fields"}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400
    
    #Verificar permissão
    cursor = conn.cursor()
    
    active_role = conn.execute("SELECT role_name FROM session_role WHERE session_id = ?;", (session_id,)).fetchone()
    
    perms = []
    if active_role:
        active_role = active_role[0]
        cursor.execute("SELECT perm_name FROM role_permissions WHERE org_id = ? AND role_name = ?", (org_id, active_role))
        perms.extend([row[0] for row in cursor.fetchall()])

        if "SUBJECT_NEW" not in perms:
            conn.close()
            return jsonify(sign_data_coms({"error": "No permission to add a subject."}, load_rep_privkey())), 403
    
    else:
        return jsonify(sign_data_coms({"error": "You have no active role."}, load_rep_privkey())), 400
    #Fim
    
    subject_exists = conn.execute("SELECT 1 FROM subject WHERE username = ?", (username,)).fetchone()

    if not subject_exists:
        conn.execute('INSERT INTO subject (full_name, email, username) VALUES (?, ?, ?)', (name, email, username))
        conn.commit()

    id = conn.execute('SELECT id FROM subject WHERE username = ?', (username,)).fetchone()[0]

    conn.execute('INSERT INTO organization_member (subject_id, org_id, pub_key, subject_status) VALUES (?,?,?,?)', (id,org_id,pub_key,status))
    conn.commit()

    result = {
        "message": "Subject created successfully"
    }

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    data_str_signed = sign_data_coms(data_str, load_rep_privkey())

    conn.close()

    return data_str_signed, 201

@app.route("/document", methods=['POST'])
def add_document():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())
    data = json.loads(data_decrypted)

    org_id = data["org_id"] 
    subject_id = data["subject_id"]
    content = data["content"]
    document_name = data["document_name"]
    alg = data["alg"]
    key = data["key"]
    file_handle = data["file_handle"]
    creation_date = datetime.date.today()
    signature = data["signature"]

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, subject_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, subject_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, subject_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, subject_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not all([org_id, subject_id, content, document_name, alg, key, creation_date]):
        return jsonify(sign_data_coms({"error": "Missing required fields"}, load_rep_privkey())), 400

    subject_exists = conn.execute("SELECT * FROM subject WHERE id = ?", (subject_id,)).fetchone()

    if not subject_exists:
        conn.close()
        return jsonify(sign_data_coms({"error": "Subject  does not exist"}, load_rep_privkey())), 400
    
    org_exists = conn.execute("SELECT * FROM organization WHERE id = ?", (org_id,)).fetchone()

    if not org_exists:
        conn.close()
        return jsonify(sign_data_coms({"error": "Organization does not exist"}, load_rep_privkey())), 400
    
    org_subject_assoc = conn.execute("SELECT 1 FROM organization_member WHERE subject_id = ? AND org_id = ?", (subject_id, org_id,)).fetchone()

    if not org_subject_assoc:
        conn.close()
        return jsonify(sign_data_coms({"error": "This subject is not associated with this organization"}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, subject_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400
    
    doc_with_same_name = conn.execute("SELECT 1 FROM document WHERE org_id = ? AND doc_name = ?", (org_id, document_name)).fetchone()
    if doc_with_same_name:
        conn.close()
        return jsonify(sign_data_coms({"error": "There is already a document with this name on the current organization. Duplicate document names are not allowed."}, load_rep_privkey())), 400
    
    # verify if the role has the permission DOC_NEW
    role = conn.execute("SELECT role_name FROM session_role WHERE subject_id = ? AND org_id = ?;", (subject_id, org_id)).fetchone()
    
    perms = []
    cursor = conn.cursor()

    if role:
        cursor.execute("SELECT perm_name FROM role_permissions WHERE org_id = ? AND role_name = ?", (org_id, role[0],))
        perms.extend([row[0] for row in cursor.fetchall()])

    else:
        conn.close()
        return jsonify(sign_data_coms({"error": "No valid role."}, load_rep_privkey())), 403

    if "DOC_NEW" not in perms:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid permission."}, load_rep_privkey())), 403

    conn.execute('INSERT INTO file_info (file_key,content,alg,sim_key) VALUES (?,?,?,?)', (file_handle, content, alg, key))
    conn.commit()

    conn.execute('INSERT INTO document (doc_name, create_date, creator_id, org_id, file_handle) VALUES (?,?,?,?,?)', (document_name, creation_date, subject_id, org_id, file_handle))
    conn.commit()

    # add all permissions to the role manager for the document (DOC_READ, DOC_DELETE, DOC_ACL)
    doc_id = conn.execute("SELECT document_handle FROM document WHERE creator_id = ? AND doc_name = ? AND org_id = ?", (subject_id, document_name, org_id)).fetchone()[0]
    all_perms = conn.execute("SELECT perm_name FROM document_acl").fetchall()

    for perm in all_perms:
        perm_name = perm[0]
        conn.execute("INSERT INTO document_role_permissions (org_id, role_name, perm_name, doc_id) VALUES (?, ?, ?, ?)", (org_id, "manager", perm_name, doc_id))
        conn.commit()

    if role[0] != "manager":
        for perm in all_perms:
            perm_name = perm[0]
            conn.execute("INSERT INTO document_role_permissions (org_id, role_name, perm_name, doc_id) VALUES (?, ?, ?, ?)", (org_id, role[0], perm_name, doc_id))
            conn.commit()     

    conn.close()

    result = {
        "message": "Document created successfully"
    }

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    data_str_signed = sign_data_coms(data_str, load_rep_privkey())

    return data_str_signed, 201

@app.route("/file", methods=['GET'])
def get_file():
    #decrypt data
    data_bytes = string_bytes(request.get_json())
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())
    data = json.loads(data_decrypted)
    
    file_handle = data["file_handle"]
    
    conn = get_db_connection()
    file_record = conn.execute(
        "SELECT content FROM file_info WHERE file_key = ?", (file_handle,)
    ).fetchone()
    conn.close()

    if not file_record:
        return jsonify({"error": "File not found"}), 404

    file_content = file_record["content"]

    file_stream = BytesIO(file_content.encode("utf-8"))

    # send the file to the client
    return send_file(
        file_stream,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=f"file_{file_handle}.txt"
    )

@app.route("/subject/list", methods=['GET'])
def list_subjects():
    conn = get_db_connection()

    #decrypted data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)
    org_id = data["org_id"]
    sub_id = data["sub_id"]
    signature = data["signature"]
    
    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    if "username" in data:
        username = data["username"] # Optional: filter by username
    else:
        username = None

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not org_id:
        return jsonify(sign_data_coms({"error": "Missing organization ID"}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    try:
        if username:
            # Query to get a specific subject
            subject = conn.execute(
                """
                SELECT s.username, s.full_name, s.email, om.subject_status 
                FROM subject s
                JOIN organization_member om ON s.id = om.subject_id
                WHERE om.org_id = ? AND s.username = ?
                """,
                (org_id, username)
            ).fetchone()

            if not subject:
                return jsonify(sign_data_coms({"error": "Subject not found"}, load_rep_privkey())), 404

            result = {
                "username": subject["username"],
                "name": subject["full_name"],
                "email": subject["email"],
                "status": subject["subject_status"]
            }

            #encrypt data
            data_encrypted = encrypt_data(json.dumps(result), session_key)
            data_str = bytes_to_string(data_encrypted)
            
            data_str_signed = sign_data_coms(data_str, load_rep_privkey())

            return data_str_signed, 200

        else:
            # Query to get all subjects
            subjects = conn.execute(
                """
                SELECT s.username, s.full_name, s.email, om.subject_status 
                FROM subject s
                JOIN organization_member om ON s.id = om.subject_id
                WHERE om.org_id = ?
                """,
                (org_id,)
            ).fetchall()

            result = [
                {
                    "username": subject["username"],
                    "name": subject["full_name"],
                    "email": subject["email"],
                    "status": subject["subject_status"]
                }
                for subject in subjects
            ]

            conn.close()

            #encrypt data
            data_encrypted = encrypt_data(json.dumps(result), session_key)
            data_str = bytes_to_string(data_encrypted)
            
            data_str_signed = sign_data_coms(data_str, load_rep_privkey())

            return data_str_signed, 200
    
    except Exception as e:
        return jsonify(sign_data_coms({"error": f"An error occurred: {str(e)}"}, load_rep_privkey())), 500
    finally:
        conn.close()

@app.route("/subject/suspend", methods=['POST'])
def suspend_subject():
    conn = get_db_connection()

    #decrypted data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data.get("org_id")
    sub_id = data.get("sub_id")
    username = data.get("username")
    signature = data["signature"]

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not org_id or not username:
        return jsonify(sign_data_coms({"error": "Missing organization ID or username"}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400
    
    #Verificar permissão
    cursor = conn.cursor()

    active_role = conn.execute("SELECT role_name FROM session_role WHERE session_id = ?;", (session_id,)).fetchone()
    
    perms = []
    if active_role:
        active_role = active_role[0]
        cursor.execute("SELECT perm_name FROM role_permissions WHERE org_id = ? AND role_name = ?", (org_id, active_role))
        perms.extend([row[0] for row in cursor.fetchall()])

        if "SUBJECT_DOWN" not in perms:
            conn.close()
            return jsonify(sign_data_coms({"error": "No permission to suspend a subject."}, load_rep_privkey())), 403
    
    else:
        return jsonify(sign_data_coms({"error": "You have no active role."}, load_rep_privkey())), 400
    #Fim

    try:
        # Check if the subject exists in the organization
        subject = conn.execute(
            """
            SELECT om.subject_id, om.subject_status
            FROM organization_member om
            JOIN subject s ON om.subject_id = s.id
            WHERE om.org_id = ? AND s.username = ?
            """,
            (org_id, username)
        ).fetchone()

        if not subject:
            return jsonify(sign_data_coms({"error": "Subject not found in the organization"}, load_rep_privkey())), 404
        
        if sub_id == subject["subject_id"]:
            return jsonify(sign_data_coms({"error": "Can not suspend myself."}, load_rep_privkey())), 400
        
        #evitar suspender o subject se ele tiver o role 'manager'.
        cursor.execute("SELECT role_name FROM member_roles WHERE subject_id = ? AND org_id = ?;", (subject["subject_id"], org_id))
        roles2 = [row[0] for row in cursor.fetchall()]

        if "manager" in roles2:
            return jsonify(sign_data_coms({"error": "Can not suspend a subject with the manager role."}, load_rep_privkey())), 400
        
        if subject["subject_status"] == "suspended":
            return jsonify(sign_data_coms({"error": "This subject is already suspended."}, load_rep_privkey())), 400

        # Update the status to 'suspended'
        conn.execute(
            "UPDATE organization_member SET subject_status = 'suspended' WHERE subject_id = ? AND org_id = ?",
            (subject["subject_id"], org_id)
        )
        conn.commit()

        result = {
            "message": f"Subject '{username}' has been suspended."
        }

        #encrypt data
        data_encrypted = encrypt_data(json.dumps(result), session_key)
        data_str = bytes_to_string(data_encrypted)

        data_str_signed = sign_data_coms(data_str, load_rep_privkey())

        return data_str_signed, 200
    except Exception as e:
        return jsonify(sign_data_coms({"error": f"An error occurred: {str(e)}"}, load_rep_privkey())), 500
    finally:
        conn.close()
    
@app.route("/subject/activate", methods=['POST'])
def activate_subject():
    conn = get_db_connection()

    #decrypted data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data.get("org_id")
    sub_id = data.get("sub_id")
    username = data.get("username")
    signature = data["signature"]

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not org_id or not username:
        return jsonify(sign_data_coms({"error": "Missing organization ID or username"}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]
    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    #Verificar permissão
    cursor = conn.cursor()

    active_role = conn.execute("SELECT role_name FROM session_role WHERE session_id = ?;", (session_id,)).fetchone()
    
    perms = []
    if active_role:
        active_role = active_role[0]
        cursor.execute("SELECT perm_name FROM role_permissions WHERE org_id = ? AND role_name = ?", (org_id, active_role))
        perms.extend([row[0] for row in cursor.fetchall()])

        if "SUBJECT_UP" not in perms:
            conn.close()
            return jsonify(sign_data_coms({"error": "No permission to activate a subject."}, load_rep_privkey())), 403

    else:
        return jsonify(sign_data_coms({"error": "You have no active role."}, load_rep_privkey())), 400
    #Fim
    
    try:
        # Check if the subject exists in the organization
        subject = conn.execute(
            """
            SELECT om.subject_id, om.subject_status  
            FROM organization_member om
            JOIN subject s ON om.subject_id = s.id
            WHERE om.org_id = ? AND s.username = ?
            """,
            (org_id, username)
        ).fetchone()

        if not subject:
            return jsonify(sign_data_coms({"error": "Subject not found in the organization"}, load_rep_privkey())), 404
        
        if sub_id == subject["subject_id"]:
            return jsonify(sign_data_coms({"error": "Can not suspend myself."}, load_rep_privkey())), 400
        
        if subject["subject_status"] == "active":
            return jsonify(sign_data_coms({"error": "This subject is already active."}, load_rep_privkey())), 400
        
        # Update the status to 'active'
        conn.execute(
            "UPDATE organization_member SET subject_status = 'active' WHERE subject_id = ? AND org_id = ?",
            (subject["subject_id"], org_id)
        )
        conn.commit()

        result = {
            "message": f"Subject '{username}' has been activated."
        }

        #encrypt data
        data_encrypted = encrypt_data(json.dumps(result), session_key)
        data_str = bytes_to_string(data_encrypted)

        data_str_signed = sign_data_coms(data_str, load_rep_privkey())

        return data_str_signed, 200
    except Exception as e:
        return jsonify(sign_data_coms({"error": f"An error occurred: {str(e)}"}, load_rep_privkey())), 500
    finally:
        conn.close()

@app.route("/document", methods=['GET'])
def list_docs():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data.get("org_id")
    subject_id = data.get("subject_id")
    username = data.get("username")
    date = data.get("date")
    date_filter = data.get("date_filter")
    signature = data.get("signature")

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, subject_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, subject_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, subject_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, subject_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not org_id or not subject_id:
        return jsonify({"error": "Missing required fields"}), 400

    try:
        if date:
            date = datetime.datetime.strptime(date, "%d-%m-%Y").date()
    except ValueError:
        return jsonify(sign_data_coms({"error": "Invalid date format. Use DD-MM-YYYY."}), load_rep_privkey()), 400

    query = "SELECT * FROM document WHERE org_id = ?"
    params = [org_id]

    if username:
        subject = conn.execute("SELECT * FROM subject WHERE username = ?", (username,)).fetchone()
        if subject:
            user_id = subject["id"] 
            query += " AND creator_id = ?"
            params.append(user_id)
        else:
            return jsonify(sign_data_coms({"error": "There is no subject with the given username associated with this organization"}, load_rep_privkey())), 400
        
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, subject_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    if date and date_filter:
        if date_filter == "nt":  
            query += " AND create_date > ?"
            params.append(date)
        elif date_filter == "ot":  
            query += " AND create_date < ?"
            params.append(date)
        elif date_filter == "et":  
            query += " AND create_date = ?"
            params.append(date)
        else:
            return jsonify(sign_data_coms({"error": "Invalid date filter."}, load_rep_privkey())), 400

    documents = conn.execute(query, params).fetchall()
    result = [dict(doc) for doc in documents]  

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    data_str_signed = sign_data_coms(data_str, load_rep_privkey())

    return data_str_signed, 200

@app.route("/metadata", methods=['GET'])
def get_metadata():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data["org_id"]
    doc_name = data["document"]
    sub_id = data["sub_id"]
    signature = data["signature"]

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not all([org_id, doc_name]):
        return jsonify(sign_data_coms({"error": "Missing required fields"}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400
    
    # verify if the role has the permission DOC_READ
    role = conn.execute("SELECT role_name FROM session_role WHERE subject_id = ? AND org_id = ?;", (sub_id, org_id)).fetchone()

    # fetch document id
    doc_id = conn.execute("SELECT document_handle FROM document WHERE doc_name = ? AND org_id = ?", (doc_name, org_id,)).fetchone()

    if not doc_id:
        conn.close()
        return jsonify(sign_data_coms({"error": "Document does not exist"}, load_rep_privkey())), 404
    
    doc_id = doc_id[0]
    perms = []
    cursor = conn.cursor()

    if role:
        cursor.execute("SELECT perm_name FROM document_role_permissions WHERE org_id = ? AND role_name = ? AND doc_id = ?", (org_id, role[0], doc_id,))
        perms.extend([row[0] for row in cursor.fetchall()])

    else:
        conn.close()
        return jsonify(sign_data_coms({"error": "No valid role."}, load_rep_privkey())), 403

    if "DOC_READ" not in perms:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid permission."}, load_rep_privkey())), 403

    doc_exists = conn.execute("SELECT * FROM document WHERE doc_name = ? AND org_id = ?", (doc_name, org_id,)).fetchone()

    if not doc_exists:
        conn.close()
        return jsonify(sign_data_coms({"error": "Document does not exist"}, load_rep_privkey())), 404

    file_handle = doc_exists[6]
    create_date = doc_exists[2]
    creator_id = doc_exists[3]
    deleter_id = doc_exists[5]

    file_info = conn.execute("SELECT * FROM file_info WHERE file_key = ?", (file_handle,)).fetchone()

    conn.close()

    result = {
        "file_handle": file_handle, 
        "alg": file_info["alg"], 
        "key": file_info["sim_key"], 
        "create_date": create_date, 
        "creator_id": creator_id,
        "deleter_id": deleter_id
    }

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    data_str_signed = sign_data_coms(data_str, load_rep_privkey())

    return data_str_signed, 200

@app.route("/document/file", methods=['GET'])
def get_doc_file():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data.get("org_id")
    subject_id = data.get("subject_id")
    doc_name = data.get("doc_name")
    signature = data["signature"]

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, subject_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, subject_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, subject_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, subject_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not all([org_id, doc_name]):
        return jsonify(sign_data_coms({"error": "Missing required fields"}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, subject_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400
    
    # verify if the role has the permission DOC_READ
    role = conn.execute("SELECT role_name FROM session_role WHERE subject_id = ? AND org_id = ?;", (subject_id, org_id)).fetchone()

    # fetch document id
    doc_id = conn.execute("SELECT document_handle FROM document WHERE doc_name = ? AND org_id = ?", (doc_name, org_id,)).fetchone()

    if not doc_id:
        conn.close()
        return jsonify(sign_data_coms({"error": "Document does not exist"}, load_rep_privkey())), 404
    
    doc_id = doc_id[0]
    perms = []
    cursor = conn.cursor()

    if role:
        cursor.execute("SELECT perm_name FROM document_role_permissions WHERE org_id = ? AND role_name = ? AND doc_id = ?", (org_id, role[0], doc_id,))
        perms.extend([row[0] for row in cursor.fetchall()])

    else:
        conn.close()
        return jsonify(sign_data_coms({"error": "No valid role."}, load_rep_privkey())), 403

    if "DOC_READ" not in perms:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid permission."}, load_rep_privkey())), 403
    
    doc_exists = conn.execute("SELECT * FROM document WHERE doc_name = ? AND org_id = ?", (doc_name, org_id,)).fetchone()

    if not doc_exists:
        conn.close()
        return jsonify(sign_data_coms({"error": "Document does not exist"}, load_rep_privkey())), 404
    
    file_handle = doc_exists[6]

    if not file_handle:
        conn.close()
        return jsonify(sign_data_coms({"error": "There is no file associated with this document."}, load_rep_privkey())), 404

    file_info = conn.execute("SELECT * FROM file_info WHERE file_key = ?", (file_handle,)).fetchone()

    conn.close()

    result = {
        "file_handle": file_handle, 
        "alg": file_info["alg"], 
        "key": file_info["sim_key"], 
        "content": file_info["content"]
    }

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    data_str_signed = sign_data_coms(data_str, load_rep_privkey())

    return data_str_signed, 200

@app.route("/role", methods=['POST'])
def add_role():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data["org_id"]
    sub_id = data["sub_id"]
    role_name = data["role"]
    signature = data["signature"]

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not all([org_id, sub_id, role_name]):
        return jsonify(sign_data_coms({"error": "Missing required fields"}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    org_exists = conn.execute("SELECT * FROM organization WHERE id = ?", (org_id,)).fetchone()
    role_exists = conn.execute("SELECT 1 FROM [role] WHERE role_name = ? AND org_id = ?",(role_name, org_id)).fetchone()

    #Verificar permissão
    cursor = conn.cursor()

    active_role = conn.execute("SELECT role_name FROM session_role WHERE session_id = ?;", (session_id,)).fetchone()
    
    perms = []
    if active_role:
        active_role = active_role[0]
        cursor.execute("SELECT perm_name FROM role_permissions WHERE org_id = ? AND role_name = ?", (org_id, active_role))
        perms.extend([row[0] for row in cursor.fetchall()])

        if "ROLE_NEW" not in perms:
            conn.close()
            return jsonify(sign_data_coms({"error": "No permission to add a role."}, load_rep_privkey())), 403

    else:
        return jsonify(sign_data_coms({"error": "You have no active role."}, load_rep_privkey())), 400
    #Fim

    if org_exists and role_exists is None:
        conn.execute("INSERT INTO role (org_id, role_name) VALUES (?, ?)", (org_id, role_name,))
        conn.commit()
    else:
        return jsonify(sign_data_coms({"error": "Error creating role."}, load_rep_privkey())), 404

    conn.close()

    result = {
        "message": "Role created successfully."
    }

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    data_str_signed = sign_data_coms(data_str, load_rep_privkey())

    return data_str_signed, 201

@app.route("/role/suspend", methods=['PUT'])
def suspend_role():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data["org_id"]
    sub_id = data["sub_id"]
    role_name = data["role"]
    signature = data["signature"]

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not all([org_id, sub_id, role_name]):
        return jsonify(sign_data_coms({"error": "Missing required fields"}, load_rep_privkey())), 400

    org_exists = conn.execute("SELECT * FROM organization WHERE id = ?", (org_id,)).fetchone()
    role_exists = conn.execute("SELECT 1 FROM [role] WHERE role_name = ? AND org_id = ?",(role_name, org_id)).fetchone()

    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

   #Verificar permissão
    cursor = conn.cursor()

    active_role = conn.execute("SELECT role_name FROM session_role WHERE session_id = ?;", (session_id,)).fetchone()
    
    role_perms = []
    if org_exists and role_exists:
        # Retrieve session details
        session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
        session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

        # Verify signature
        if not verify_signature_coms(request.get_json(), session_key):
            conn.close()
            return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

        # Get role-specific permissions
        cursor.execute("SELECT perm_name FROM role_permissions WHERE org_id = ? AND role_name = ?", (org_id, role_name))
        role_perms = [row[0] for row in cursor.fetchall()]

        # Get document-specific permissions
        cursor.execute("SELECT document_id, perm_name FROM document_role_permissions WHERE org_id = ? AND role_name = ?", (org_id, role_name))
        doc_permissions = cursor.fetchall()

        # Group permissions by document_id
        doc_perms_dict = {}
        for document_id, perm_name in doc_permissions:
            if document_id not in doc_perms_dict:
                doc_perms_dict[document_id] = []
            doc_perms_dict[document_id].append(perm_name)

        # Add grouped document permissions to role_perms
        for document_id, perms in doc_perms_dict.items():
            role_perms.append(f"document_id: {document_id} - {', '.join(perms)}")

    else:
        conn.close()
        return jsonify(sign_data_coms({"error": "Error retrieving permission list for the given role."}, load_rep_privkey())), 404

    # Handle empty permissions list
    if not role_perms:
        conn.close()
        return jsonify(sign_data_coms({"error": "This role does not have any permission."}, load_rep_privkey())), 404

    # Close connection
    conn.close()

    # Prepare and encrypt response
    result = {
        "message": role_perms
    }

    # Encrypt and sign data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)
    data_str_signed = sign_data_coms(data_str, load_rep_privkey())

    return data_str_signed, 201


@app.route("/role/reactivate", methods=['PUT'])
def reactivate_role():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data["org_id"]
    sub_id = data["sub_id"]
    role_name = data["role"]
    signature = data["signature"]

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not all([org_id, sub_id, role_name]):
        return jsonify(sign_data_coms({"error": "Missing required fields"}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    org_exists = conn.execute("SELECT * FROM organization WHERE id = ?", (org_id,)).fetchone()
    role_exists = conn.execute("SELECT 1 FROM [role] WHERE role_name = ? AND org_id = ?",(role_name, org_id)).fetchone()

    #Verificar permissão
    cursor = conn.cursor()

    active_role = conn.execute("SELECT role_name FROM session_role WHERE session_id = ?;", (session_id,)).fetchone()
    
    perms = []
    if active_role:
        active_role = active_role[0]
        cursor.execute("SELECT perm_name FROM role_permissions WHERE org_id = ? AND role_name = ?", (org_id, active_role))
        perms.extend([row[0] for row in cursor.fetchall()])

        if "ROLE_UP" not in perms:
            conn.close()
            return jsonify(sign_data_coms({"error": "No permission to activate a role."}, load_rep_privkey())), 403

    else:
        return jsonify(sign_data_coms({"error": "You have no active role."}, load_rep_privkey())), 400
    #Fim

    if org_exists and role_exists:
        # Check if the role is already active
        current_status = conn.execute("SELECT role_status FROM role WHERE org_id = ? AND role_name = ?",(org_id, role_name)).fetchone()

        if current_status and current_status['role_status'] == 'ACTIVE':
            return jsonify(sign_data_coms({"message": "This role is already active."}, load_rep_privkey())), 200
        
        # Update the status to 'ACTIVE'
        conn.execute(
            "UPDATE role SET role_status = 'ACTIVE' WHERE org_id = ? AND role_name = ?",
            (org_id, role_name)
        )
        conn.commit()
    else:
        return jsonify(sign_data_coms({"error": "Error reactivating role."}, load_rep_privkey())), 404

    conn.close()

    result = {
        "message": "Role reactivated successfully."
    }

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    data_str_signed = sign_data_coms(data_str, load_rep_privkey())

    return data_str_signed, 201


@app.route("/role/permissions", methods=['GET'])
def get_role_permissions():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data["org_id"]
    sub_id = data["sub_id"]
    role_name = data["role"]
    signature = data["signature"]

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not all([org_id, sub_id, role_name]):
        return jsonify(sign_data_coms({"error": "Missing required fields"}, load_rep_privkey())), 400

    cursor = conn.cursor()

    org_exists = conn.execute("SELECT * FROM organization WHERE id = ?", (org_id,)).fetchone()
    role_exists = conn.execute("SELECT 1 FROM [role] WHERE role_name = ? AND org_id = ?",(role_name, org_id)).fetchone()

    role_perms = []
    if org_exists and role_exists:
        # Retrieve session details
        session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
        session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

        # Verify signature
        if not verify_signature_coms(request.get_json(), session_key):
            conn.close()
            return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

        cursor.execute("SELECT perm_name FROM role_permissions WHERE org_id = ? AND role_name = ?", (org_id, role_name))
        role_perms = [row[0] for row in cursor.fetchall()]

        cursor.execute("SELECT doc_id, perm_name FROM document_role_permissions WHERE org_id = ? AND role_name = ?", (org_id, role_name))
        doc_permissions = cursor.fetchall()

        # Group permissions by document_id
        doc_perms_dict = {}
        for document_id, perm_name in doc_permissions:
            if document_id not in doc_perms_dict:
                doc_perms_dict[document_id] = []
            doc_perms_dict[document_id].append(perm_name)

        for document_id, perms in doc_perms_dict.items():
            role_perms.append(f"document_id: {document_id} - {', '.join(perms)}")

    else:
        conn.close()
        return jsonify(sign_data_coms({"error": "Error retrieving permission list for the given role."}, load_rep_privkey())), 404

    if not role_perms:
        conn.close()
        return jsonify(sign_data_coms({"error": "This role does not have any permission."}, load_rep_privkey())), 404

    conn.close()

    result = {
        "message": role_perms
    }

    # Encrypt and sign data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)
    data_str_signed = sign_data_coms(data_str, load_rep_privkey())

    return data_str_signed, 201


    
@app.route("/permission/roles", methods=['GET'])
def get_permission_roles():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data["org_id"]
    sub_id = data["sub_id"]
    perm_name = data["permission"]
    signature = data["signature"]

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not all([org_id, sub_id, perm_name]):
        return jsonify(sign_data_coms({"error": "Missing required fields"}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    no_roles = False
    conn.row_factory = sqlite3.Row 
    cursor = conn.cursor()
    
    # Fetch all roles with the permission
    cursor.execute("SELECT role_name FROM role_permissions WHERE perm_name = ? AND org_id=?;", (perm_name,org_id))
    all_roles = [row["role_name"] for row in cursor.fetchall()]

    if all_roles == []:
        query_roles_by_document = """
            SELECT doc_id, role_name
            FROM document_role_permissions
            WHERE perm_name = ? AND org_id=?;
        """

        # Execute the query
        cursor.execute(query_roles_by_document, (perm_name,org_id))
        doc_roles = cursor.fetchall()

        # Group roles by doc_id
        doc_roles_dict = {}
        for doc_id, role_name in doc_roles:
            if doc_id not in doc_roles_dict:
                doc_roles_dict[doc_id] = []
            doc_roles_dict[doc_id].append(role_name)

        # Format the result list
        all_roles = [f"doc_id: {doc_id} - {', '.join(roles)}" for doc_id, roles in doc_roles_dict.items()]

    if all_roles == []:
        conn.close()
        return jsonify(sign_data_coms({"error": "No role has this permission."}, load_rep_privkey())), 404

    result = {
        "message": all_roles
    }
    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    data_str_signed = sign_data_coms(data_str, load_rep_privkey())

    return data_str_signed, 201
    
@app.route("/permission", methods=['POST'])
def add_permission():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data["org_id"]
    sub_id = data["sub_id"]
    role_name = data["role"]
    permission = data["permission"]
    signature = data["signature"]

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not all([org_id, sub_id, role_name, permission]):
        return jsonify(sign_data_coms({"error": "Missing required fields"}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400
    
    #Verificar permissão
    cursor = conn.cursor()

    active_role = conn.execute("SELECT role_name FROM session_role WHERE session_id = ?;", (session_id,)).fetchone()
    
    perms = []
    if active_role:
        active_role = active_role[0]
        cursor.execute("SELECT perm_name FROM role_permissions WHERE org_id = ? AND role_name = ?", (org_id, active_role))
        perms.extend([row[0] for row in cursor.fetchall()])

        if "ROLE_MOD" not in perms:
            conn.close()
            return jsonify(sign_data_coms({"error": "No permission to add a permission to a role."}, load_rep_privkey())), 403

    else:
        return jsonify(sign_data_coms({"error": "You have no active role."}, load_rep_privkey())), 400
    #Fim

    # verify if the role exists in the organization
    role_exists = conn.execute("SELECT 1 FROM [role] WHERE role_name = ? AND org_id = ?",(role_name, org_id)).fetchone()

    if not role_exists:
        conn.close()
        return jsonify(sign_data_coms({"error": "Role does not exist."}, load_rep_privkey())), 404
    
    cursor.execute("SELECT perm_name FROM role_permissions WHERE org_id = ? AND role_name = ?", (org_id, role_name))
    role_perms=[row[0] for row in cursor.fetchall()]

    if permission in role_perms:
        return jsonify(sign_data_coms({"error": "This role already have the provided permission"}, load_rep_privkey())), 403

    conn.execute("INSERT INTO role_permissions (org_id, role_name, perm_name) VALUES (?,?,?)",(org_id, role_name, permission))
    conn.commit()
    
    conn.close()

    result = {
        "message": "Permission successfully added."
    }

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    data_str_signed = sign_data_coms(data_str, load_rep_privkey())

    return data_str_signed, 201


@app.route("/permission/username", methods=['POST'])
def add_permission_username():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data["org_id"]
    sub_id = data["sub_id"]
    role_name = data["role"]
    username = data["username"]
    signature = data["signature"]

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not all([org_id, sub_id, role_name, username]):
        return jsonify(sign_data_coms({"error": "Missing required fields"}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400
    
    #Verificar permissão
    cursor = conn.cursor()

    active_role = conn.execute("SELECT role_name FROM session_role WHERE session_id = ?;", (session_id,)).fetchone()
    
    perms = []
    if active_role:
        active_role = active_role[0]
        cursor.execute("SELECT perm_name FROM role_permissions WHERE org_id = ? AND role_name = ?", (org_id, active_role))
        perms.extend([row[0] for row in cursor.fetchall()])

        if "ROLE_MOD" not in perms:
            conn.close()
            return jsonify(sign_data_coms({"error": "No permission to add a role to a subject."}, load_rep_privkey())), 403

    else:
        return jsonify(sign_data_coms({"error": "You have no active role."}, load_rep_privkey())), 400
    #Fim
    
    new_sub_id = conn.execute("SELECT id FROM subject WHERE username = ?", (username,)).fetchone()

    if not new_sub_id:
        conn.close()
        return jsonify(sign_data_coms({"error": "There is no subject with the provided username."}, load_rep_privkey())), 404
    
    new_sub_id = new_sub_id[0]
    
    cursor.execute("SELECT role_name FROM member_roles WHERE subject_id = ? AND org_id = ?;", (new_sub_id, org_id))
    roles = [row[0] for row in cursor.fetchall()]

    if role_name in roles:
        return jsonify(sign_data_coms({"error": "This subject already has this role."}, load_rep_privkey())), 403

    conn.execute("INSERT INTO member_roles (subject_id, org_id, role_name) VALUES (?,?,?)", (new_sub_id, org_id, role_name))
    conn.commit()

    conn.close()

    result = {
        "message": "Role added to subject successfully."
    }

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    data_str_signed = sign_data_coms(data_str, load_rep_privkey())

    return data_str_signed, 201



@app.route("/permission", methods=['DELETE'])
def remove_permission():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data["org_id"]
    sub_id = data["sub_id"]
    role_name = data["role"]
    permission = data["permission"]
    signature = data["signature"]

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not all([org_id, sub_id, role_name, permission]):
        return jsonify(sign_data_coms({"error": "Missing required fields"}, load_rep_privkey())), 400
    
    if role_name == "manager":
        return jsonify(sign_data_coms({"error": "Cannot remove a permission from the manager role."}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    #Verificar permissão
    cursor = conn.cursor()

    active_role = conn.execute("SELECT role_name FROM session_role WHERE session_id = ?;", (session_id,)).fetchone()
    
    perms = []
    if active_role:
        active_role = active_role[0]
        cursor.execute("SELECT perm_name FROM role_permissions WHERE org_id = ? AND role_name = ?", (org_id, active_role))
        perms.extend([row[0] for row in cursor.fetchall()])

        if "ROLE_MOD" not in perms:
            conn.close()
            return jsonify(sign_data_coms({"error": "No permission to remove a permission from a role."}, load_rep_privkey())), 403

    else:
        return jsonify(sign_data_coms({"error": "You have no active role."}, load_rep_privkey())), 400
    #Fim

    # verify if the role exists in the organization
    role_exists = conn.execute("SELECT 1 FROM [role] WHERE role_name = ? AND org_id = ?",(role_name, org_id)).fetchone()

    if not role_exists:
        conn.close()
        return jsonify(sign_data_coms({"error": "Role does not exist."}, load_rep_privkey())), 404
    
    cursor.execute("SELECT perm_name FROM role_permissions WHERE org_id = ? AND role_name = ?", (org_id, role_name))
    role_perms=[row[0] for row in cursor.fetchall()]

    if permission not in role_perms:
        return jsonify(sign_data_coms({"error": "This role does not have the provided permission"}, load_rep_privkey())), 403

    conn.execute("DELETE FROM role_permissions where org_id = ? and role_name = ? and perm_name = ?",(org_id, role_name, permission))
    conn.commit()
    
    conn.close()

    result = {
        "message": "Permission successfully removed."
    }

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    data_str_signed = sign_data_coms(data_str, load_rep_privkey())

    return data_str_signed, 201


@app.route("/permission/username", methods=['DELETE'])
def remove_permission_username():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data["org_id"]
    sub_id = data["sub_id"]
    role_name = data["role"]
    username = data["username"]
    signature = data["signature"]

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not all([org_id, sub_id, role_name, username]):
        return jsonify(sign_data_coms({"error": "Missing required fields"}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    #Verificar permissão
    cursor = conn.cursor()

    active_role = conn.execute("SELECT role_name FROM session_role WHERE session_id = ?;", (session_id,)).fetchone()
    
    perms = []
    if active_role:
        active_role = active_role[0]
        cursor.execute("SELECT perm_name FROM role_permissions WHERE org_id = ? AND role_name = ?", (org_id, active_role))
        perms.extend([row[0] for row in cursor.fetchall()])

        if "ROLE_MOD" not in perms:
            conn.close()
            return jsonify(sign_data_coms({"error": "No permission to remove a role from a subject."}, load_rep_privkey())), 403

    else:
        return jsonify(sign_data_coms({"error": "You have no active role."}, load_rep_privkey())), 400
    #Fim
    
    new_sub_id = conn.execute("SELECT id FROM subject WHERE username = ?", (username,)).fetchone()

    if not new_sub_id:
        conn.close()
        return jsonify(sign_data_coms({"error": "There is no subject with the provided username."}, load_rep_privkey())), 404
    
    new_sub_id = new_sub_id[0]

    cursor.execute("SELECT role_name FROM member_roles WHERE subject_id = ? AND org_id = ?;", (new_sub_id, org_id))
    roles = [row[0] for row in cursor.fetchall()]

    if role_name not in roles:
        return jsonify(sign_data_coms({"error": "This subject does not have this role."}, load_rep_privkey())), 403
    
    if role_name == "manager":
        cursor.execute("SELECT subject_id FROM member_roles WHERE org_id = ? AND role_name = ?", (org_id, "manager"))
        manager_list = [row[0] for row in cursor.fetchall()]

        if len(manager_list) < 2 :
            return jsonify(sign_data_coms({"error": "Unable to remove manager role. Must have atleast one subject with manager role."}, load_rep_privkey())), 400

    conn.execute("DELETE FROM member_roles WHERE subject_id = ? AND org_id = ? AND role_name = ?", (new_sub_id, org_id, role_name))
    conn.commit()
    
    conn.close()

    result = {
        "message": "Role removed from subject successfully."
    }

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    data_str_signed = sign_data_coms(data_str, load_rep_privkey())

    return data_str_signed, 201

@app.route("/doc_acl", methods=['POST'])
def doc_acl():
    conn = get_db_connection()

    #decrypted data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data["org_id"]
    sub_id = data["sub_id"]
    doc_name = data["document"]
    role_name = data["role"]
    signature = data["signature"]
    permission = data["permission"]
    is_adding = data["action"]

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

    if permission not in ["DOC_ACL", "DOC_READ", "DOC_DELETE"]:
        conn.close()
        return jsonify(sign_data_coms({"error": "Permission does not apply to documents."}, load_rep_privkey())), 400

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not all([org_id, sub_id, doc_name, role_name, permission]):
        return jsonify(sign_data_coms({"error": "Missing required fields"}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400
    
    role = conn.execute("SELECT role_name FROM session_role WHERE subject_id = ? AND org_id = ?;", (sub_id, org_id)).fetchone()

    perms = []
    cursor = conn.cursor()

    if role:
        cursor.execute("SELECT perm_name FROM document_role_permissions WHERE org_id = ? AND role_name = ?", (org_id, role[0],))
        perms.extend([row[0] for row in cursor.fetchall()])

    else:
        conn.close()
        return jsonify(sign_data_coms({"error": "No valid role."}, load_rep_privkey())), 403

    if "DOC_ACL" not in perms:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid permission."}, load_rep_privkey())), 403
    
    # fetch document id
    doc_id = conn.execute("SELECT document_handle FROM document WHERE org_id = ? AND doc_name = ?", (org_id, doc_name)).fetchone()

    if not doc_id:
        conn.close()
        return jsonify(sign_data_coms({"error": "Document does not exist."}, load_rep_privkey())), 404
    
    doc_id = doc_id[0]
    
    perms = []
    cursor.execute("SELECT perm_name FROM document_role_permissions WHERE org_id = ? AND role_name = ? AND doc_id = ?", (org_id, role_name, doc_id,))
    perms.extend([row[0] for row in cursor.fetchall()])

    if is_adding and permission in perms:
        return jsonify(sign_data_coms({"error": "This role already has the provided permission"}, load_rep_privkey())), 403
    
    if not is_adding and permission not in perms:
        return jsonify(sign_data_coms({"error": "This role does not have the provided permission"}, load_rep_privkey())), 403
    
    if not is_adding and role[0] == "manager":
        return jsonify(sign_data_coms({"error": "Cannot remove a permission from the manager role."}, load_rep_privkey())), 403

    if is_adding:
        conn.execute("INSERT INTO document_role_permissions (org_id, role_name, doc_id, perm_name) VALUES (?,?,?,?)", (org_id, role_name, doc_id, permission))
        conn.commit()

    else:
        conn.execute("DELETE FROM document_role_permissions WHERE org_id = ? AND role_name = ? AND doc_id = ? AND perm_name = ?", (org_id, role_name, doc_id, permission))
        conn.commit()

    conn.close()

    result = {
        "message": f"Permission {'added' if is_adding else 'removed'} to role successfully."
    }

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    data_str_signed = sign_data_coms(data_str, load_rep_privkey())

    return data_str_signed, 201

@app.route("/role", methods=['GET'])
def list_roles():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data["org_id"]
    sub_id = data["sub_id"]
    signature = data["signature"]
    
    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not all([org_id, sub_id]):
        return jsonify(sign_data_coms({"error": "Missing required fields"}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    subject = conn.execute(
            """
            SELECT om.subject_status
            FROM organization_member om
            JOIN subject s ON om.subject_id = s.id
            WHERE om.org_id = ? AND s.id = ?
            """,
            (org_id, sub_id)
        ).fetchone()
    
    if subject["subject_status"] == 'suspended':
        return jsonify(sign_data_coms({"error": "You are currently suspended and can not perform actions."}, load_rep_privkey())), 400

    cursor = conn.cursor()
    
    print("org_id:",org_id)
    print("type:", type(org_id))
    cursor.execute("SELECT role_name FROM [role] WHERE org_id = ?",(org_id,))
    org_roles = [row[0] for row in cursor.fetchall()]

    conn.close()

    result = {
        "message": org_roles
    }

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    data_str_signed = sign_data_coms(data_str, load_rep_privkey())

    return data_str_signed, 201

@app.route("/role/subjects", methods=['GET'])
def list_role_subjects():
    conn = get_db_connection()

    try:
        # Decrypt incoming data
        payload = request.get_json()["payload_sign"]
        data_bytes = string_bytes(payload)
        data_decrypted = decrypt_data(data_bytes, load_rep_privkey())
        data = json.loads(data_decrypted)

        org_id = data.get("org_id")
        sub_id = data.get("sub_id")
        role_name = data.get("role_name")
        nonce = data.get("nonce")
        seq_num = data.get("seq_num")
        signature = data.get("signature")

        # Validate required fields
        if not all([org_id, sub_id, role_name, nonce, seq_num, signature]):
            return jsonify(sign_data_coms({"error": "Missing required fields."}, load_rep_privkey())), 400

        # Verify signature
        pub_key = load_rep_pubkey()
        signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)
        if not signature_valid:
            return jsonify(sign_data_coms({"error": "Invalid signature."}, load_rep_privkey())), 400

        # Validate session lifetime
        if not check_session_lifetime(conn, org_id, sub_id):
            return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400

        # Verify nonce and sequence number
        if not verify_nonce(conn, org_id, sub_id, nonce) or not verify_seq_num(conn, org_id, sub_id, seq_num):
            return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number."}, load_rep_privkey())), 400

        # Validate subject's status in the organization
        subject = conn.execute(
            """
            SELECT om.subject_status
            FROM organization_member om
            JOIN subject s ON om.subject_id = s.id
            WHERE om.org_id = ? AND s.id = ?
            """,
            (org_id, sub_id)
        ).fetchone()

        if not subject or subject["subject_status"] == "suspended":
            return jsonify(sign_data_coms({"error": "You are currently suspended and cannot perform actions."}, load_rep_privkey())), 400
        
        # Fetch session key for encryption
        session_id = conn.execute(
            "SELECT id FROM session WHERE org_id = ? AND subject_id = ?", 
            (org_id, sub_id)
        ).fetchone()[0]
        session_key = conn.execute(
            "SELECT session_key FROM session_keys WHERE session_id = ?", 
            (session_id,)
        ).fetchone()[0]

        if not verify_signature_coms(request.get_json(), session_key):
            conn.close()
            return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

        # Validate role existence and status
        role = conn.execute(
            """
            SELECT role_name
            FROM [role]
            WHERE org_id = ? AND role_name = ? AND role_status = 'ACTIVE'
            """,
            (org_id, role_name)
        ).fetchone()

        if not role:
            return jsonify(sign_data_coms({"error": f"Role '{role_name}' does not exist or is inactive."}, load_rep_privkey())), 404

        # Fetch subjects associated with the role
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT s.full_name, s.username, s.email
            FROM member_roles mr
            JOIN subject s ON mr.subject_id = s.id
            WHERE mr.org_id = ? AND mr.role_name = ?
            """,
            (org_id, role_name)
        )
        role_subjects = [
            {"full_name": row[0], "username": row[1], "email": row[2]}
            for row in cursor.fetchall()
        ]

        # Prepare the result
        result = {"message": role_subjects}

        # Encrypt and sign the result
        encrypted_data = encrypt_data(json.dumps(result), session_key)
        encrypted_string = bytes_to_string(encrypted_data)
        signed_response = sign_data_coms(encrypted_string, load_rep_privkey())

        return signed_response, 201

    except Exception as e:
        return jsonify(sign_data_coms({"error": f"An error occurred: {str(e)}"}, load_rep_privkey())), 500

    finally:
        conn.close()

@app.route("/subject/roles", methods=['GET'])
def list_subject_roles():
    conn = get_db_connection()
    
    try:
        # Decrypt request data
        payload = request.get_json()["payload_sign"]
        data_bytes = string_bytes(payload)
        data_decrypted = decrypt_data(data_bytes, load_rep_privkey())
        data = json.loads(data_decrypted)

        org_id = data.get("org_id")
        subject_id = data.get("sub_id")
        username = data.get("username")
        nonce = data.get("nonce")
        seq_num = data.get("seq_num")
        signature = data.get("signature")

        # Validate required fields
        if not all([org_id, subject_id, username, nonce, seq_num, signature]):
            return jsonify(sign_data_coms({"error": "Missing required fields."}, load_rep_privkey())), 400

        # Session validation
        sub_id = conn.execute(
            "SELECT id FROM subject WHERE username = ?", (username,)
        ).fetchone()
        if not sub_id:
            return jsonify(sign_data_coms({"error": f"User '{username}' not found."}, load_rep_privkey())), 404

        sub_id = sub_id[0]

        pub_key = load_rep_pubkey()
        signature_valid = verify_signature(conn, org_id, subject_id, signature, pub_key)

        if not signature_valid:
            conn.close()
            return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

        valid_session = check_session_lifetime(conn, org_id, subject_id)
        if not valid_session:
            return jsonify(sign_data_coms({"error": "Session expired."}, load_rep_privkey())), 400

        if not verify_nonce(conn, org_id, subject_id, nonce):
            return jsonify(sign_data_coms({"error": "Invalid nonce."}, load_rep_privkey())), 400

        if not verify_seq_num(conn, org_id, subject_id, seq_num):
            return jsonify(sign_data_coms({"error": "Invalid sequence number."}, load_rep_privkey())), 400
        
        session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, subject_id)).fetchone()[0]
        session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

        if not verify_signature_coms(request.get_json(), session_key):
            conn.close()
            return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

        # Fetch roles
        roles = conn.execute(
            "SELECT role_name FROM member_roles WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)
        ).fetchall()
        role_list = [role["role_name"] for role in roles]

        # Encrypt and sign response
        result = {"message": role_list}
        
        encrypted_response = encrypt_data(json.dumps(result), session_key)
        response_str = bytes_to_string(encrypted_response)

        return sign_data_coms(response_str, load_rep_privkey()), 200

    except Exception as e:
        return jsonify(sign_data_coms({"error": f"An error occurred: {str(e)}"}, load_rep_privkey())), 500
    finally:
        conn.close()

@app.route("/role/assume", methods=['POST'])
def assume_role():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json()["payload_sign"])
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data["org_id"]
    sub_id = data["sub_id"]
    role_name = data["role"]
    signature = data["signature"]

    pub_key = load_rep_pubkey()
    signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

    if not signature_valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

    if not all([org_id, sub_id, role_name]):
        return jsonify(sign_data_coms({"error": "Missing required fields"}, load_rep_privkey())), 400
    
    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    if not verify_signature_coms(request.get_json(), session_key):
        conn.close()
        return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

    org_exists = conn.execute("SELECT * FROM organization WHERE id = ?", (org_id,)).fetchone()

    #Verificar permissão
    cursor = conn.cursor()

    cursor.execute("SELECT role_name FROM member_roles WHERE subject_id = ? AND org_id = ?", (sub_id, org_id))
    subject_roles = [row[0] for row in cursor.fetchall()]

    active_role = conn.execute("SELECT role_name FROM session_role WHERE session_id = ?;", (session_id,)).fetchone()
    
    if active_role:
        return jsonify(sign_data_coms({"error": "Drop your role before assuming a new one."}, load_rep_privkey())), 400

    if org_exists and role_name in subject_roles:
        current_status = conn.execute("SELECT role_status FROM role WHERE org_id = ? AND role_name = ?",(org_id, role_name)).fetchone()

        if current_status[0] != "ACTIVE":
            return jsonify(sign_data_coms({"error": "This role is suspended."}, load_rep_privkey())), 400

    else:
        return jsonify(sign_data_coms({"error": "Error assuming roles."}, load_rep_privkey())), 404
    
    conn.execute("INSERT INTO session_role (session_id, subject_id, org_id, role_name) VALUES (?, ?, ?, ?)", (session_id, sub_id, org_id, role_name))
    conn.commit()

    conn.close()

    result = {
        "message": f"Role '{role_name}' assumed successfully."
    }

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    data_str_signed = sign_data_coms(data_str, load_rep_privkey())

    return data_str_signed, 201

@app.route("/role/drop", methods=['POST'])
def drop_role():
    conn = get_db_connection()

    try:
        # Decrypt and parse the request payload
        data_bytes = string_bytes(request.get_json()["payload_sign"])
        data_decrypted = decrypt_data(data_bytes, load_rep_privkey())
        data = json.loads(data_decrypted)

        org_id = data["org_id"]
        sub_id = data["sub_id"]
        role_name = data["role"]
        signature = data["signature"]

        # Validate signature
        pub_key = load_rep_pubkey()
        signature_valid = verify_signature(conn, org_id, sub_id, signature, pub_key)

        if not signature_valid:
            return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

        # Check session validity
        valid = check_session_lifetime(conn, org_id, sub_id)
        if not valid:
            return jsonify(sign_data_coms({"error": "Session expired. Please create a new session."}, load_rep_privkey())), 400

        # Verify nonce and sequence number
        nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
        num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

        if not nonce_valid or not num_seq_verified:
            return jsonify(sign_data_coms({"error": "Invalid nonce or sequence number"}, load_rep_privkey())), 400

        # Get session ID
        session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()

        if not session_id:
            return jsonify(sign_data_coms({"error": "Session not found."}, load_rep_privkey())), 404
        session_id = session_id[0]

        session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

        if not verify_signature_coms(request.get_json(), session_key):
            conn.close()
            return jsonify(sign_data_coms({"error": "Invalid signature"}, load_rep_privkey())), 400

        # Check if a role is active
        active_role = conn.execute("SELECT role_name FROM session_role WHERE session_id = ?;", (session_id,)).fetchone()
        if not active_role:
            return jsonify(sign_data_coms({"error": "No active role to drop."}, load_rep_privkey())), 400
        elif active_role[0] != role_name:
            print(active_role, "!=", role_name)
            return jsonify(sign_data_coms({"error": "This role does not match the active role."}, load_rep_privkey())), 400

        # Remove the active role
        conn.execute("DELETE FROM session_role WHERE session_id = ?;", (session_id,))
        conn.commit()

        result = {
            "message": "Role dropped successfully."
        }

        # Encrypt and sign the response
        data_encrypted = encrypt_data(json.dumps(result), session_key)
        data_str = bytes_to_string(data_encrypted)
        data_str_signed = sign_data_coms(data_str, load_rep_privkey())

        return data_str_signed, 201

    except Exception as e:
        return jsonify(sign_data_coms({"error": str(e)}, load_rep_privkey())), 500
    finally:
        conn.close()

if __name__ == "__main__":
    verify_password()
    populate_acl()
    app.run(debug=True)
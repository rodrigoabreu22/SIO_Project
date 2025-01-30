from flask import Flask, request, jsonify, json, send_file
import sqlite3
import datetime
from cryptography.hazmat.primitives import hashes
import sys
from decrypt_command import decrypt_data, string_bytes, load_rep_privkey
from encrypt_command import encrypt_data, bytes_to_string
from cryptography.hazmat.primitives import serialization
from io import BytesIO

app = Flask(__name__)
MASTER_KEY = b'\xb2\x96\xd0R\xa9=\xce\x83R\xd5\x8d\xc3\\\x940,rU\xee\x9c_+\x06\xd9\x9dq*l\x07\x1bJ\x13'
SESSION_LIFETIME = 6000
DATE_FORMAT = "%Y-%m-%d %H:%M:%S.%f"

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


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


@app.route("/organization/list", methods=["GET"])
def list_organizations():
    conn = get_db_connection()
    try:
        orgs = conn.execute("SELECT id, org_name FROM organization").fetchall()
        conn.close()

        organizations = [{"id": org["id"], "org_name": org["org_name"]} for org in orgs]

        return jsonify({"organizations": organizations}), 200
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
    data = request.get_json()
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
        return jsonify({"error": "Organization already exists"}), 400

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

    conn.close()

    return jsonify({"message": "Organization created successfully"}), 201

@app.route("/document", methods=['DELETE'])
def delete_document():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json())
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data["org_id"]
    sub_id = data["sub_id"] 
    doc_name = data["document"]

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify({"error": "Session expired. Please create a new session."}), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify({"error": "Invalid nonce or sequence number"}), 400

    file_handle = conn.execute("SELECT file_handle FROM document WHERE doc_name = ? AND org_id = ?", (doc_name, org_id,)).fetchone()[0]
    if not file_handle:
        conn.close()
        return jsonify({"error": "There is no document with the given file_handle."}), 400
        

    file_tuple = conn.execute("SELECT alg, sim_key FROM file_info WHERE file_key = ?", (file_handle,)).fetchone()

    #make file_handle null
    conn.execute("UPDATE document SET file_handle = NULL WHERE doc_name = ? AND org_id = ?", (doc_name, org_id,))
    conn.commit()

    conn.execute("UPDATE document SET deleter_id = ? WHERE doc_name = ? AND org_id = ?", (sub_id, doc_name, org_id,))
    conn.commit()

    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    conn.close()

    result = {
        "file_handle": file_handle,
        "alg": file_tuple["alg"],
        "key": file_tuple["sim_key"]
    }

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
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

    if not all([org_id, username, session_key]):
        conn.close()
        return jsonify({"error": "Missing required fields"}), 400

    # check if organization exists
    org = conn.execute("SELECT * FROM organization WHERE id = ?", (org_id,)).fetchone()[0]
    if not org:
        conn.close()
        return jsonify({"error": "Organization not found"}), 404

    sub_id = conn.execute("SELECT id FROM subject WHERE username = ?", (username,)).fetchone()[0]
    if not sub_id:
        conn.close()
        return jsonify({"error": "Subject not found"}), 404
    
    last_interaction = datetime.datetime.now()  
    print(last_interaction)
    conn.execute("INSERT INTO session (org_id, subject_id, last_interaction) VALUES (?, ?, ?)", (org_id, sub_id, last_interaction))
    conn.commit()

    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]

    conn.execute("INSERT INTO session_keys (session_id, session_key) VALUES (?, ?)", (session_id, session_key))
    conn.commit()
    conn.close()

    response = {
        "sub_id": sub_id,
        "last_interaction": last_interaction
    }

    #return encrypted data
    data_encrypted = encrypt_data(json.dumps(response), session_key)
    data_str = bytes_to_string(data_encrypted)

    return data_str, 200

@app.route("/subject", methods=['POST'])
def add_subject():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json())
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)
    org_id = data["org_id"] 
    sub_id = data["sub_id"]
    username = data["username"]
    name = data["name"]
    email = data["email"]
    pub_key = data["public_key"]
    role = "default"
    status = "active"

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify({"error": "Session expired. Please create a new session."}), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify({"error": "Invalid nonce or sequence number"}), 400

    if not all([org_id, username, name, email, pub_key]):
        return jsonify({"error": "Missing required fields"}), 400
    
    subject_exists = conn.execute("SELECT 1 FROM subject WHERE username = ?", (username,)).fetchone()

    if not subject_exists:
        conn.execute('INSERT INTO subject (full_name, email, username) VALUES (?, ?, ?)', (name, email, username))
        conn.commit()

    id = conn.execute('SELECT id FROM subject WHERE username = ?', (username,)).fetchone()[0]

    conn.execute('INSERT INTO organization_member (subject_id, org_id, pub_key, subject_status) VALUES (?,?,?,?)', (id,org_id,pub_key,status))
    conn.commit()
    
    conn.execute('INSERT INTO member_roles (subject_id, org_id, role_name) VALUES (?,?,?)', (id, org_id, role))
    conn.commit()

    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    result = {
        "message": "Subject created successfully"
    }

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    conn.close()

    return data_str, 201

@app.route("/document", methods=['POST'])
def add_document():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json())
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

    valid = check_session_lifetime(conn, org_id, subject_id)

    if not valid:
        conn.close()
        return jsonify({"error": "Session expired. Please create a new session."}), 400
    
    nonce_valid = verify_nonce(conn, org_id, subject_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, subject_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify({"error": "Invalid nonce or sequence number"}), 400

    if not all([org_id, subject_id, content, document_name, alg, key, creation_date]):
        return jsonify({"error": "Missing required fields"}), 400

    subject_exists = conn.execute("SELECT * FROM subject WHERE id = ?", (subject_id,)).fetchone()

    if not subject_exists:
        conn.close()
        return jsonify({"error": "Subject  does not exist"}), 400
    
    org_exists = conn.execute("SELECT * FROM organization WHERE id = ?", (org_id,)).fetchone()

    if not org_exists:
        conn.close()
        return jsonify({"error": "Organization does not exist"}), 400
    
    org_subject_assoc = conn.execute("SELECT 1 FROM organization_member WHERE subject_id = ? AND org_id = ?", (subject_id, org_id,)).fetchone()

    if not org_subject_assoc:
        conn.close()
        return jsonify({"error": "This subject is not associated with this organization"}), 400
    
    doc_with_same_name = conn.execute("SELECT 1 FROM document WHERE org_id = ? AND doc_name = ?", (org_id, document_name)).fetchone()
    if doc_with_same_name:
        conn.close()
        return jsonify({"error": "There is already a document with this name on the current organization. Duplicate document names are not allowed."}), 400

    conn.execute('INSERT INTO file_info (file_key,content,alg,sim_key) VALUES (?,?,?,?)', (file_handle, content, alg, key))
    conn.commit()

    conn.execute('INSERT INTO document (doc_name, create_date, creator_id, org_id, file_handle) VALUES (?,?,?,?,?)', (document_name, creation_date, subject_id, org_id, file_handle))
    conn.commit()

    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, subject_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    conn.close()

    result = {
        "message": "Document created successfully"
    }

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    return data_str, 201

@app.route("/file", methods=['GET'])
def get_file():

    data = request.get_json()
    file_handle = data["file_handle"]
    
    conn = get_db_connection()
    file_record = conn.execute(
        "SELECT content FROM file_info WHERE id = file_handle", (file_handle,)
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
    data_bytes = string_bytes(request.get_json())
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)
    org_id = data["org_id"]
    sub_id = data["sub_id"]
    if "username" in data:
        username = data["username"] # Optional: filter by username
    else:
        username = None

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify({"error": "Session expired. Please create a new session."}), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify({"error": "Invalid nonce or sequence number"}), 400

    if not org_id:
        return jsonify({"error": "Missing organization ID"}), 400

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
                return jsonify({"error": "Subject not found"}), 404

            result = {
                "username": subject["username"],
                "name": subject["full_name"],
                "email": subject["email"],
                "status": subject["subject_status"]
            }
            return jsonify(result), 200

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

            session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
            session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

            conn.close()

            #encrypt data
            data_encrypted = encrypt_data(json.dumps(result), session_key)
            data_str = bytes_to_string(data_encrypted)

            return data_str, 200
    
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500
    finally:
        conn.close()

@app.route("/subject/suspend", methods=['POST'])
def suspend_subject():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json())
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data.get("org_id")
    sub_id = data.get("sub_id")
    username = data.get("username")

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify({"error": "Session expired. Please create a new session."}), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify({"error": "Invalid nonce or sequence number"}), 400

    if not org_id or not username:
        return jsonify({"error": "Missing organization ID or username"}), 400

    try:
        # Check if the subject exists in the organization
        subject = conn.execute(
            """
            SELECT om.subject_id 
            FROM organization_member om
            JOIN subject s ON om.subject_id = s.id
            WHERE om.org_id = ? AND s.username = ?
            """,
            (org_id, username)
        ).fetchone()

        if not subject:
            return jsonify({"error": "Subject not found in the organization"}), 404

        # Update the status to 'suspended'
        conn.execute(
            "UPDATE organization_member SET subject_status = 'suspended' WHERE subject_id = ? AND org_id = ?",
            (subject["subject_id"], org_id)
        )
        conn.commit()

        session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
        session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

        result = {
            "message": f"Subject '{username}' has been suspended."
        }

        #encrypt data
        data_encrypted = encrypt_data(json.dumps(result), session_key)
        data_str = bytes_to_string(data_encrypted)

        return data_str, 200
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500
    finally:
        conn.close()
    
@app.route("/subject/activate", methods=['POST'])
def activate_subject():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json())
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data.get("org_id")
    sub_id = data.get("sub_id")
    username = data.get("username")
    role = data.get("role", "default")  # Default role if not specified

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify({"error": "Session expired. Please create a new session."}), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify({"error": "Invalid nonce or sequence number"}), 400

    if not org_id or not username:
        return jsonify({"error": "Missing organization ID or username"}), 400

    try:
        # Check if the subject exists in the organization
        subject = conn.execute(
            """
            SELECT om.subject_id 
            FROM organization_member om
            JOIN subject s ON om.subject_id = s.id
            WHERE om.org_id = ? AND s.username = ?
            """,
            (org_id, username)
        ).fetchone()

        if not subject:
            return jsonify({"error": "Subject not found in the organization"}), 404

        # Update the status to 'active'
        conn.execute(
            "UPDATE organization_member SET subject_status = 'active' WHERE subject_id = ? AND org_id = ?",
            (subject["subject_id"], org_id)
        )
        conn.commit()

        session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
        session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

        result = {
            "message": f"Subject '{username}' has been activated."
        }

        #encrypt data
        data_encrypted = encrypt_data(json.dumps(result), session_key)
        data_str = bytes_to_string(data_encrypted)

        return data_str, 200
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500
    finally:
        conn.close()

@app.route("/document", methods=['GET'])
def list_docs():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json())
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data.get("org_id")
    subject_id = data.get("subject_id")
    username = data.get("username")
    date = data.get("date")
    date_filter = data.get("date_filter")

    valid = check_session_lifetime(conn, org_id, subject_id)

    if not valid:
        conn.close()
        return jsonify({"error": "Session expired. Please create a new session."}), 400
    
    nonce_valid = verify_nonce(conn, org_id, subject_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, subject_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify({"error": "Invalid nonce or sequence number"}), 400

    if not org_id or not subject_id:
        return jsonify({"error": "Missing required fields"}), 400

    try:
        if date:
            date = datetime.datetime.strptime(date, "%d-%m-%Y").date()
    except ValueError:
        return jsonify({"error": "Invalid date format. Use DD-MM-YYYY."}), 400

    query = "SELECT * FROM document WHERE org_id = ?"
    params = [org_id]

    if username:
        subject = conn.execute("SELECT * FROM subject WHERE username = ?", (username,)).fetchone()
        if subject:
            user_id = subject["id"] 
            query += " AND creator_id = ?"
            params.append(user_id)
        else:
            return jsonify({"error": "There is no subject with the given username associated with this organization"}), 400

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
            return jsonify({"error": "Invalid date filter."}), 400

    documents = conn.execute(query, params).fetchall()
    result = [dict(doc) for doc in documents]  

    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, subject_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

    #encrypt data
    data_encrypted = encrypt_data(json.dumps(result), session_key)
    data_str = bytes_to_string(data_encrypted)

    return data_str, 200

@app.route("/metadata", methods=['GET'])
def get_metadata():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json())
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data["org_id"]
    doc_name = data["document"]
    sub_id = data["sub_id"]

    valid = check_session_lifetime(conn, org_id, sub_id)

    if not valid:
        conn.close()
        return jsonify({"error": "Session expired. Please create a new session."}), 400
    
    nonce_valid = verify_nonce(conn, org_id, sub_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, sub_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify({"error": "Invalid nonce or sequence number"}), 400

    if not all([org_id, doc_name]):
        return jsonify({"error": "Missing required fields"}), 400

    doc_exists = conn.execute("SELECT * FROM document WHERE doc_name = ? AND org_id = ?", (doc_name, org_id,)).fetchone()

    if not doc_exists:
        conn.close()
        return jsonify({"error": "Document does not exist"}), 404

    file_handle = doc_exists[6]
    create_date = doc_exists[2]
    creator_id = doc_exists[3]
    deleter_id = doc_exists[5]

    file_info = conn.execute("SELECT * FROM file_info WHERE file_key = ?", (file_handle,)).fetchone()

    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, sub_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

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

    return data_str, 200

@app.route("/document/file", methods=['GET'])
def get_doc_file():
    conn = get_db_connection()

    #decrypt data
    data_bytes = string_bytes(request.get_json())
    data_decrypted = decrypt_data(data_bytes, load_rep_privkey())

    data = json.loads(data_decrypted)

    org_id = data.get("org_id")
    subject_id = data.get("subject_id")
    doc_name = data.get("doc_name")

    valid = check_session_lifetime(conn, org_id, subject_id)

    if not valid:
        conn.close()
        return jsonify({"error": "Session expired. Please create a new session."}), 400
    
    nonce_valid = verify_nonce(conn, org_id, subject_id, data["nonce"])
    num_seq_verified = verify_seq_num(conn, org_id, subject_id, data["seq_num"])

    if not nonce_valid or not num_seq_verified:
        conn.close()
        return jsonify({"error": "Invalid nonce or sequence number"}), 400

    if not all([org_id, doc_name]):
        return jsonify({"error": "Missing required fields"}), 400
    
    doc_exists = conn.execute("SELECT * FROM document WHERE doc_name = ? AND org_id = ?", (doc_name, org_id,)).fetchone()

    if not doc_exists:
        conn.close()
        return jsonify({"error": "Document does not exist"}), 404
    
    file_handle = doc_exists[6]

    if not file_handle:
        conn.close()
        return jsonify({"error": "There is no file associated with this document."}), 404

    file_info = conn.execute("SELECT * FROM file_info WHERE file_key = ?", (file_handle,)).fetchone()

    session_id = conn.execute("SELECT id FROM session WHERE org_id = ? AND subject_id = ?", (org_id, subject_id)).fetchone()[0]
    session_key = conn.execute("SELECT session_key FROM session_keys WHERE session_id = ?", (session_id,)).fetchone()[0]

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

    return data_str, 200

if __name__ == "__main__":
    verify_password()
    app.run(debug=True)

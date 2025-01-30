# Group members
- Rodrigo Abreu, 113626
- Eduardo Lopes, 103070
- Raquel Vinagre, 113736


## Features
- Create a key pair for a subject
- Decrypt file
- Create organization
- List organizations
- Create session
- Get file
- List subjects
- List documents
- Add subject
- Suspend subject
- Activate subject
- Add document
- Get doc metadata
- Get doc file
- Delete doc


## Notes 
The repository asymetric keys are stored in a .env file. 
We implemented a relational SQLLite database to store the necessary data in a peristent and organized way.
The db schema is provided in the file: schema.sql
To initialize the db, you should run the following command:
```bash
python3 init_db.py
```

Run the repository:
```
python3 repository.py
```

## Communication Notes
The encryption of communications with the repository was implemented using a hybrid cipher. A 32-byte symmetric key was generated and used to encrypt the payload sent to the repository. Subsequently, the MAC (Message Authentication Code) of the encrypted content was calculated using another 32-byte key. Finally, everything was encrypted with the recipient's public key (either the repository's or the session's public key).

The payload also includes the encrypted nonce (calculated during the encryption process) to ensure the uniqueness of the message, as well as the sequence number to guarantee the order of the messages.


## Commands implemented
##### 1.
```bash
rep_subject_credentials <password> <credentials file>
```
This command creates an asymetric key pair using RSA. The private key is encrypted with the provided password. The private key and public key are stored on different files in a directory named credentials.

##### 2. 
```bash
rep_decrypt_file <encrypted file> <encryption metadata>
```
This command will decrypt the cyphered text either directly as argument, or stored in a file, which its path is passed as argument. The decryption algorithm is AES CBC, and the metadata provided has the necessary data to decrypt it (salt, iv, key). 

The file_handle is also provided for integrity control. The same digest function used to generate the file handle, will be applied on the provided cypher text and compared with the file_handle to verify if the file content was altered. 

The decrypted content will be sent to the stdout.

##### 3. 
```bash
rep_create_org <organization> <username> <name> <email> <public key file>
```
Creates an organization and a subject (organization member). Both are stored on the database on the tables "organization", "subject" and "organization_member".

##### 4. 
```bash
rep_list_orgs
```
Lists all existing organizations (stored on the db).

##### 5.
```bash
rep_create_session <organization> <username> <password> <credentials file> <session file>
```
Note: We pass the organization_id as arg to organization.

This commands creates a subject session in the provided organization. 

This session will have a limited time of inactivity, and its core info is stored in the session file (org_id, subject_id, last interaction, session private key)

In the database we store the data in the session table (org_id, subject_id, last interaction) and in the session_keys table (public key)

##### 6.
```bash
rep_get_file <file handle> [file]
```
Given a file handle, it searches for a file (file_info table in the db) with the file_handle provided (file_key in the db). 

If a file is provided, the cyphered content is written in the file, else it is send to the stdout. 

Deleted files can be accessed with this command.

##### 7.
```bash
rep_list_subjects <session file> [username]
```
Lists all subjects of the organization provided on the session file. (Search the organization_member and subject tables)
If a username is provided returns the subject with the corresponding username.

##### 8.
```bash
rep_list_docs <session file> [-s username] [-d nt/ot/et date]
```
Lists all documents of the organization provided on the session file. (Search the document table)

If username is provided lists the documents created by this subject if exists in this organization.

It is possible also filter the documents with creation date newer, older or equal to a provided date.

##### 9.
```bash
rep_add_subject <session file> <username> <name> <email> <credentials file>
```
Adds a new subject to the organization provided on the session file. (Stores in the subject table and organization_member)

##### 10.
```bash
rep_suspend_subject <session file> <username>
rep_activate_subject <session file> <username>
```
Commands used to change the status of a subject in the organization provided on the session file. Status is an attribute in the organization_member table.

We will explore it more on the 2nd delivery.

##### 11.
```bash
rep_add_doc <session file> <document name> <file>
```
This command adds a document to the organization provided on the session file, with the subject provided on the session file as creator. This document is stored on the document db and the respective document information. The file is stored in the file_info table with the encryption algorithm (alg), key, and the file_key as primary key. The document as file_handle as primary key, which references the file_info file_key.

The content of the file is encrypted in the following way:
We generate a random key and derive it using PBKDF2 and a random salt, than we create a random iv and use it with the key to encrypt the file using the AES CBC algorithm. 

The  alg field contains the algorithm, the salt and the iv, so the subject that access this metadata is able to decrypt the file.
 
##### 12.
```bash
rep_get_doc_metadata <session file> <document name>
```
This command gets the metadata of the document in the provided organization (on the session file). The metadata includes the private and public metadata stored in the file_info and document tables in the db.

#### 13.
```bash
rep_get_doc_file <session file> <document name> [file]
```
This command gets the file of the document and the necessary metadata to decrypt it using the decryption method mention before. If an output file is provided, writes de decrypted content in the file, else sends it to the std_out.

#### 14.
```bash
rep_delete_doc <session file> <document name>
```

This command searchs the document table and sets the file_handle null and sets the deleter_id the subject_id provided on the session file.

#### Testing


## Testing all the commands

### Create a key pair for a subject:
```bash
    ./rep_subject_credentials "banana" "credentials/credential.pem" 
```

### Creating an organization:
```bash
    ./rep_create_org "MyOrg1" "user1" "User One" "user1@example.com" "credentials/pub_key.pem" 
```

### Listing all organizations:
```bash
    ./rep_list_orgs
```

### Create session:
```bash
     ./rep_create_session "1" "user1" "banana" "credentials/credential.pem" "session/sessionFile.json"
```

### Decrypt file:
```bash
    ./rep_decrypt_file "encrypted_file.txt" "metadata/document_name.json"
```

### Get file: 
```bash
    python3 
```

### Add subject:
```bash
    ./rep_add_subject "session/sessionFile.json" "username" "name" "username@ua.pt" "credentials/credential.pem"
```

### List subjects:
```bash
    ./rep_list_subjects "session/sessionFile.json" "username"
```

### Suspend subject:
```bash
    ./rep_suspend_subject "session/sessionFile.json" "username" 
```

### Activate subject:
```bash
    ./rep_activate_subject "session/sessionFile.json" "username" 
```

### Add document:
```bash
    ./rep_add_doc "session/sessionFile.json" "document1" "files/doc1.txt"
```

### List documents:
```bash
    ./rep_list_docs -s "username" -d "ot" "20-11-2024"
```

### Get doc metadata:
```bash
    ./rep_get_doc_metadata "session/sessionFile.json" "document1"
```

### Get doc file:
```bash
    ./rep_get_doc_file "session/sessionFile.json" "document1" "output_file.txt"
```

### Delete doc:
```bash
    ./rep_delete_doc "session/sessionFile.json" "document1"
```


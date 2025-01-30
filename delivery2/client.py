import os
import sys
import argparse
import logging
import json
import requests
# from auxiliar_functions import create_key_pair, save_public_key, load_public_key, write_privkey_credentials, decrypt_file, delete_document

logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def load_state():
    state = {}
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    logger.debug('State folder: ' + state_dir)
    logger.debug('State file: ' + state_file)

    if os.path.exists(state_file):
        logger.debug('Loading state')
        with open(state_file,'r') as f:
            state = json.loads(f.read())

    if state is None:
        state = {}

    return state

def parse_env(state):
    if 'REP_ADDRESS' in os.environ:
        state['REP_ADDRESS'] = os.getenv('REP_ADDRESS')
        logger.debug('Setting REP_ADDRESS from Environment to: ' + state['REP_ADDRESS'])

    if 'REP_PUB_KEY' in os.environ:
        rep_pub_key = os.getenv('REP_PUB_KEY')
        logger.debug('Loading REP_PUB_KEY fron: ' + state['REP_PUB_KEY'])
        if os.path.exists(rep_pub_key):
            with open(rep_pub_key, 'r') as f:
                state['REP_PUB_KEY'] = f.read()
                logger.debug('Loaded REP_PUB_KEY from Environment')
    return state

def parse_args(state):
    parser = argparse.ArgumentParser()

    parser.add_argument("-k", '--key', nargs=1, help="Path to the key file")
    parser.add_argument("-r", '--repo', nargs=1, help="Address:Port of the repository")
    parser.add_argument("-v", '--verbose', help="Increase verbosity", action="store_true")
    parser.add_argument("-c", "--command", help="Command to execute")
    parser.add_argument('arg0', nargs='?', default=None)
    parser.add_argument('arg1', nargs='?', default=None)
    parser.add_argument('arg2', nargs='?', default=None)
    parser.add_argument('arg3', nargs='?', default=None)
    parser.add_argument('arg4', nargs='?', default=None)
    parser.add_argument('arg5', nargs='?', default=None)

    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info('Setting log level to DEBUG')

    if args.key:
        if not os.path.exists(args.key[0]) or not os.path.isfile(args.key[0]):
            logger.error(f'Key file not found or invalid: {args.key[0]}')
            sys.exit(-1)

        with open(args.key[0], 'r') as f:
            state['REP_PUB_KEY'] = f.read()
            logger.info('Overriding REP_PUB_KEY from command line')

    if args.repo:
        state['REP_ADDRESS'] = args.repo[0]
        logger.info('Overriding REP_ADDRESS from command line')
    
    if args.command:
        logger.info("Command: " + args.command)
       
    return state, {'command': args.command, 'arg0': args.arg0, 'arg1': args.arg1, 'arg2': args.arg2, 'arg3': args.arg3, 'arg4': args.arg4, 'arg5': args.arg5}

def save(state):
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    if not os.path.exists(state_dir):
      logger.debug('Creating state folder')
      os.mkdir(state_dir)

    with open(state_file, 'w') as f:
        f.write(json.dumps(state, indent=4))

state = load_state()
state = parse_env(state)
state, args = parse_args(state)

if 'REP_ADDRESS' not in state:
  logger.error("Must define Repository Address")
  sys.exit(-1)

if 'REP_PUB_KEY' not in state:
  logger.error("Must set the Repository Public Key")
  sys.exit(-1)
  
""" Do something """
logger.debug("Arguments: " + str(args))

#First Delivery Commands

#rep_subject_credentials <password> <credentials file>
# def rep_subject_credentials(password, credencials_file):
#     private_key, public_key = create_key_pair(password)
#     write_privkey_credentials(credencials_file, private_key)
#     save_public_key(public_key, 'credentials/pub_key.pem')

# #rep_decrypt_file <encrypted file> <encryption metadata>
# def rep_decrypt_file(encryted_file, metadata):
#     content = decrypt_file(encryted_file, metadata)

#rep_create_org <organization> <username> <name> <email> <public key file>
# def rep_create_org(organization, username, name, email, pubkey_file):

#     try:
#         public_key = load_public_key(pubkey_file)

#         data = {
#             "organization": organization,
#             "username": username,
#             "name": name,
#             "email": email,
#             "public_key": public_key
#         }

#         base_address = state.get("REP_ADDRESS", "http://localhost:5000")
#         url = f"{base_address}/organization/create"

#         response = requests.post(url, json=data)

#         if response.status_code == 201:
#             print("Organization created successfully.")
#         else:
#             print(f"Failed to create organization: {response.status_code} {response.text}")
#     except FileNotFoundError:
#         print(f"Public key file not found: {pubkey_file}")
#         sys.exit(-1)
#     except Exception as e:
#         print(f"An error occurred while creating the organization: {str(e)}")
#         sys.exit(-1)

#rep_list_orgs
# def rep_list_orgs():
#     """Lists all organizations available on the server."""
#     try:
#         # Get the base address of the server
#         base_address = state.get("REP_ADDRESS", "http://localhost:5000")
#         url = f"{base_address}/organization/list"

#         # Make a GET request to fetch the list of organizations
#         response = requests.get(url)

#         if response.status_code == 200:
#             # Parse and print the list of organizations
#             organizations = response.json().get("organizations", [])
#             if not organizations:
#                 print("No organizations found.")
#             else:
#                 print("List of Organizations:")
#                 for org in organizations:
#                     print(f"- {org['id']}: {org['org_name']}")
#         else:
#             print(f"Failed to list organizations: {response.status_code} {response.text}")
#     except Exception as e:
#         print(f"An error occurred while listing organizations: {str(e)}")
#         sys.exit(-1)

#rep_create_session <organization> <username> <password> <credentials file> <session file>
# def rep_create_session(organization, username, password, credentials_file, session_file):
#     request = {
#         "org_id": organization,
#         "username": username,
#     }

#     response = requests.post("http://localhost:5000/session", json=request)

#     if response.status_code == 200:
#         data = response.json()
#         sub_id = data["sub_id"]

#         if os.path.exists(session_file):
#             with open(session_file, 'wb') as f:
#                 f.write(organization)
#                 f.write(sub_id)

#rep_get_file <file handle> [file]
# def rep_get_file(file_handle, file=None):
#     try:
#         base_address = state.get("REP_ADDRESS", "http://localhost:5000")
#         url = f"{base_address}/file/get/{file_handle}"

#         response = requests.get(url, stream=True)

#         if response.status_code == 200:
#             if file: #optional argument
#                 with open(file, "wb") as f:
#                     for chunk in response.iter_content(chunk_size=8192):
#                         f.write(chunk)
#                 print(f"File successfully downloaded to {file}")
#             else:
#                 for chunk in response.iter_content(chunk_size=8192):
#                     sys.stdout.buffer.write(chunk)
#         else:
#             print(f"Failed to download file: {response.status_code} {response.text}")
#     except Exception as e:
#         print(f"An error occurred while fetching the file: {str(e)}")


#rep_list_subjects <session file> [username]
# def rep_list_subjects(session_file, username=None):
#     return None

#rep_list_docs <session file> [-s username] [-d nt/ot/et date]
def rep_list_docs(session_file, username=None, date=None):
    return None

#rep_add_subject <session file> <username> <name> <email> <credentials file>
# def rep_add_subject(session_file, username, name, email, credentials_file):
#     return None

#rep_add_doc <session file> <document name> <file>
# def rep_add_doc(session_file, document_name, file):
#     return None

#rep_get_doc_metadata <session file> <document name>
def rep_get_doc_metadata(session_file, document_name):
    return None

#rep_get_doc_file <session file> <document name> [file]
def rep_get_doc_file(session_file, document_name, file=None):
    return None

#rep_delete_doc <session file> <document name>
# def rep_delete_doc(session_file, doc_name):
#     file_handle, agl, key = delete_document(session_file, doc_name)
#     print(f"File handle: {file_handle}")
#     print(f"Algorithm: {agl}")
#     print(f"Key: {key}")


# print("Program name:", args["command"])
# if args["command"] == "rep_create_org":
#     if any(arg is None for arg in [args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"]]):
#         logger.error("Missing arguments for rep_create_org")
#         sys.exit(-1)
#     rep_create_org(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])

# elif args["command"] == "rep_list_orgs":
#     rep_list_orgs()

# elif args["command"] == "rep_subject_credentials":
#     if args["arg0"] is None or args["arg1"] is None:
#         logger.error("Missing arguments for rep_subject_credentials")
#         sys.exit(-1)
#     rep_subject_credentials(args["arg0"], args["arg1"])

# elif args["command"] == "rep_decrypt_file":
#     if args["arg0"] is None or args["arg1"] is None:
#         logger.error("Missing arguments for rep_decrypt_file")
#         sys.exit(-1)
#     rep_decrypt_file(args["arg0"], args["arg1"])

# elif args["command"] == "rep_create_session":
#     if any(arg is None for arg in [args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"]]):
#         logger.error("Missing arguments for rep_create_session")
#         sys.exit(-1)
#     rep_create_session(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])

# elif args["command"] == "rep_get_file":
#     if args["arg0"] is None:
#         logger.error("Missing file handle for rep_get_file")
#         sys.exit(-1)
#     rep_get_file(args["arg0"], args["arg1"])

# elif args["command"] == "rep_list_subjects":
#     if args["arg0"] is None:
#         logger.error("Missing session file for rep_list_subjects")
#         sys.exit(-1)
#     rep_list_subjects(args["arg0"], args["arg1"])

# elif args["command"] == "rep_list_docs":
#     if args["arg0"] is None:
#         logger.error("Missing session file for rep_list_docs")
#         sys.exit(-1)
#     rep_list_docs(args["arg0"], username=args["arg1"], date=args["arg2"])

# elif args["command"] == "rep_add_subject":
#     if any(arg is None for arg in [args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"]]):
#         logger.error("Missing arguments for rep_add_subject")
#         sys.exit(-1)
#     rep_add_subject(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])

# elif args["command"] == "rep_add_doc":
#     if args["arg0"] is None or args["arg1"] is None or args["arg2"] is None:
#         logger.error("Missing arguments for rep_add_doc")
#         sys.exit(-1)
#     rep_add_doc(args["arg0"], args["arg1"], args["arg2"])

# elif args["command"] == "rep_get_doc_metadata":
#     if args["arg0"] is None or args["arg1"] is None:
#         logger.error("Missing arguments for rep_get_doc_metadata")
#         sys.exit(-1)
#     rep_get_doc_metadata(args["arg0"], args["arg1"])

# elif args["command"] == "rep_get_doc_file":
#     if args["arg0"] is None or args["arg1"] is None:
#         logger.error("Missing arguments for rep_get_doc_file")
#         sys.exit(-1)
#     rep_get_doc_file(args["arg0"], args["arg1"], args["arg2"])

# elif args["command"] == "rep_delete_doc":
#     if args["arg0"] is None or args["arg1"] is None:
#         logger.error("Missing arguments for rep_delete_doc")
#         sys.exit(-1)
#     rep_delete_doc(args["arg0"], args["arg1"])

# else:
#     logger.error("Invalid command")
#     sys.exit(-1)

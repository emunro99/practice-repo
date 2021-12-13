import hvac
import os
import logging
import requests
from dotenv import load_dotenv
from pprint import pprint

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

VAULT_ADDR = os.environ["VAULT_ADDR"]
VAULT_TOKEN = os.environ["VAULT_TOKEN"]
VAULT_MOUNT_POINT = os.environ["VAULT_MOUNT_POINT"]


def vault_authentication():
    """
    Authenticate to both versions of vault
    """

    dest_client = hvac.Client(url=VAULT_ADDR)
    dest_client.token = os.environ["VAULT_TOKEN"]

    if not dest_client.is_authenticated():
        raise ValueError(f"Invalid token for destination vault")
    print(f"Sucessfully authenticated with vault")
    return dest_client


def vault_list(vault_client, cloud, path):
    """
    A function for listing everything under a given vault path. Gets used in the functions below.
    """
    keys_list = (
        vault_client.secrets.kv.v2.list_secrets(
            path=path,
            mount_point=VAULT_MOUNT_POINT,
        )
        .get("data")
        .get("keys")
    )
    return keys_list


def read_vault_secret(source_path, client):
    """
    Read a secret from both versions of vault
    """
    try:
        read_secret_result = client.secrets.kv.v2.read_secret_version(path=source_path, mount_point=VAULT_MOUNT_POINT)["data"]
        logger.info(f"Secret Read From: {source_path}")
        return read_secret_result["data"]
    except hvac.exceptions.Forbidden:
        logger.info("Permission Denied to This Path")
        return False
    except hvac.exceptions.InvalidPath:
        logger.info(f"Path Invalid: {source_path}")
        return False



vault_client = vault_authentication()


pprint(read_vault_secret("aws/047905742371/account_info", vault_client))

account_data = read_vault_secret("aws/047905742371/account_info", vault_client)
account_id = "047905742371"
account_email = account_data['email']
account_mfa_secret = account_data['mfa_secret']


# totp_email = "test1@cloud-ops.co.uk"
# totp_mfa_string = "x"
# totp_url = f"otpauth://totp/AWS:{totp_email}?secret={totp_mfa_string}&issuer=AWS"

# request_headers = {"X-Vault-Token": VAULT_TOKEN}
# request_parameters = {"url": VAULT_ADDR}

# request_response = requests.post(VAULT_ADDR + "v1/totp/keys/angelo1", headers=request_headers, params=request_parameters)

# pprint(request_response.json())

def vault_write_totp(totp_email, totp_mfa_string):
    """
    Write TOTP code to vault
    """
    totp_url = f"otpauth://totp/AWS:{totp_email}?secret={totp_mfa_string}&issuer=AWS"
    request_headers = {"X-Vault-Token": VAULT_TOKEN}
    request_parameters = {"key": "x"}
    request_response = requests.post(VAULT_ADDR + "v1/totp/keys/angelo1", headers=request_headers, params=request_parameters)
    return request_response.json()


pprint(vault_write_totp("test1@cloud-ops.co.uk", "x"))


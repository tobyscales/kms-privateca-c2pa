## Copyright 2025 Google. 
## This software is provided as-is, without warranty or representation for any use or purpose. 
## Your use of it is subject to your agreement with Google.  

import os
import sys
from google.cloud import kms
from google.cloud import secretmanager_v1
from google.cloud.security import privateca_v1
from google.protobuf import duration_pb2
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# --- CONFIGURATION FROM ENV ---
PROJECT_ID = os.environ.get("PROJECT_ID")
LOCATION = os.environ.get("LOCATION")
CA_POOL_ID = os.environ.get("CA_POOL_ID")
TEMPLATE_ID = os.environ.get("TEMPLATE_ID")
KMS_KEY_ID = os.environ.get("KMS_KEY_ID") 
AUTHOR_SECRET_VER = os.environ.get("AUTHOR_SECRET_VER")
ORG_SECRET_VER = os.environ.get("ORG_SECRET_VER")

def get_secret_payload(client, version_name):
    """Fetches the payload from a specific Secret Manager version."""
    response = client.access_secret_version(request={"name": version_name})
    return response.payload.data.decode("UTF-8")

def get_kms_public_key(client, key_version_name):
    """Fetches the PEM-encoded public key from Cloud KMS."""
    response = client.get_public_key(request={"name": key_version_name})
    return response.pem

def clean_pem(pem):
    """Strips headers/footers for raw comparison."""
    return pem.replace("\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "")

def is_cert_valid(cert, target_key_clean, target_cn, target_org):
    """
    Checks if a cert matches BOTH the KMS Key AND the desired Identity.
    """
    if not cert.pem_certificate:
        return False
        
    try:
        # 1. Parse Cert
        cert_obj = x509.load_pem_x509_certificate(cert.pem_certificate.encode("utf-8"))
        
        # 2. Check Key Match
        cert_pub_der = cert_obj.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if clean_pem(cert_pub_der.decode('utf-8')) != target_key_clean:
            return False

        # 3. Check Subject Match (Identity Change Detection)
        # We extract the CommonName and Organization from the cert subject
        cert_cn = cert_obj.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        cert_org = cert_obj.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
        
        if cert_cn != target_cn or cert_org != target_org:
            print(f"⚠️  Key matches, but identity differs. \n   Current: {cert_cn} ({cert_org}) \n   Desired: {target_cn} ({target_org})")
            return False
            
        return True

    except Exception as e:
        print(f"⚠️ Warning: Could not parse cert {cert.name}: {e}")
        return False

def main():
    if not all([PROJECT_ID, CA_POOL_ID, KMS_KEY_ID, AUTHOR_SECRET_VER, ORG_SECRET_VER]):
        print("❌ Error: Missing required environment variables.")
        sys.exit(1)

    kms_client = kms.KeyManagementServiceClient()
    ca_client = privateca_v1.CertificateAuthorityServiceClient()
    sm_client = secretmanager_v1.SecretManagerServiceClient()

    if CA_POOL_ID.startswith("projects/"):
        ca_pool_parent = CA_POOL_ID
    else:
        ca_pool_parent = f"projects/{PROJECT_ID}/locations/{LOCATION}/caPools/{CA_POOL_ID}"

    print(f"🎯 Using CA Pool Parent: {ca_pool_parent}")
    print(f"🎯 Using Template: {TEMPLATE_ID}")

    # 1. Fetch Identity from Secrets
    print("🔐 Fetching identity from Secret Manager...")
    try:
        author_cn = get_secret_payload(sm_client, AUTHOR_SECRET_VER)
        author_org = get_secret_payload(sm_client, ORG_SECRET_VER)
        print(f"   Target Identity: CN={author_cn}, O={author_org}")
    except Exception as e:
        print(f"❌ Failed to fetch secrets: {e}")
        sys.exit(1)

    # 2. Fetch KMS Public Key
    print(f"🔑 Fetching public key for: {KMS_KEY_ID}")
    pk_pem = get_kms_public_key(kms_client, KMS_KEY_ID)
    pk_clean = clean_pem(pk_pem)

    ca_pool_parent = f"projects/{PROJECT_ID}/locations/{LOCATION}/caPools/{CA_POOL_ID}"

    # 3. Check for Existing Valid Cert
    request = privateca_v1.ListCertificatesRequest(
        parent=ca_pool_parent,
        filter="revocation_details.revocation_state = ACTIVE"
    )

    print(f"🔎 Checking existing certificates in {CA_POOL_ID}...")
    for cert in ca_client.list_certificates(request=request):
        if is_cert_valid(cert, pk_clean, author_cn, author_org):
            print(f"✅ Active certificate already exists for this Key + Identity: {cert.name}")
            return

    # 4. Provision New Cert
    print("🚀 Identity changed or no cert found. Provisioning new C2PA certificate...")
    
    certificate = privateca_v1.Certificate(
        certificate_template=TEMPLATE_ID,
        config=privateca_v1.CertificateConfig(
            subject_config=privateca_v1.CertificateConfig.SubjectConfig(
                subject=privateca_v1.Subject(
                    common_name=author_cn,
                    organization=author_org
                ),
            ),
            # Even though the Template defines the values, the API requires 
            # this object to be present (even if empty) to pass validation.
            x509_config=privateca_v1.X509Parameters(),
            public_key=privateca_v1.PublicKey(
                format_=privateca_v1.PublicKey.KeyFormat.PEM,
                key=pk_pem.encode("utf-8")
            )
        ),
        lifetime=duration_pb2.Duration(seconds=31536000) # 1 Year
    )

    request = privateca_v1.CreateCertificateRequest(
        parent=ca_pool_parent,
        certificate_id=f"c2pa-leaf-{os.urandom(4).hex()}",
        certificate=certificate
    )

    try:
        resp = ca_client.create_certificate(request=request)
        print(f"✅ Successfully created C2PA-compliant certificate: {resp.name}")
    except Exception as e:
        print(f"❌ Failed to create certificate: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

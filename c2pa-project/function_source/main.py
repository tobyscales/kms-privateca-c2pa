## Copyright 2025 Google. 
## This software is provided as-is, without warranty or representation for any use or purpose. 
## Your use of it is subject to your agreement with Google.  

import os
import hashlib
import functions_framework
import c2pa
import google_crc32c
from google.cloud import storage, secretmanager, kms
from google.cloud.security import privateca_v1
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils

# --- Global Clients ---
storage_client = storage.Client()
secret_manager_client = secretmanager.SecretManagerServiceClient()
kms_client = kms.KeyManagementServiceClient()
ca_client = privateca_v1.CertificateAuthorityServiceClient()

# Define supported formats
SUPPORTED_MIME_TYPES = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".tiff": "image/tiff",
    ".mp4": "video/mp4",
    ".mov": "video/quicktime",
    ".m4a": "audio/mp4",
    ".mp3": "audio/mpeg"
}

def get_secret(project_id, secret_id, version_id="latest"):
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
    response = secret_manager_client.access_secret_version(name=name)
    return response.payload.data.decode("UTF-8")

def der_to_raw_signature(der_bytes, curve_size_bytes=32):
    """Converts KMS DER signature to C2PA Raw (R|S) signature."""
    r, s = utils.decode_dss_signature(der_bytes)
    r_bytes = r.to_bytes(curve_size_bytes, byteorder='big')
    s_bytes = s.to_bytes(curve_size_bytes, byteorder='big')
    return r_bytes + s_bytes

def resolve_kms_version(kms_key_id: str) -> str:
    """
    Ensures we have a full CryptoKeyVersion resource name.
    If a Key ID is provided (no version), fetches the Primary Version.
    """
    if "cryptoKeyVersions" in kms_key_id:
        return kms_key_id
    
    print(f"🔑 Resolving Primary Version for Key: {kms_key_id.split('/')[-1]}")
    key = kms_client.get_crypto_key(request={"name": kms_key_id})
    
    if not key.primary:
        raise ValueError(f"KMS Key {kms_key_id} has no primary version enabled.")
        
    return key.primary.name

def get_kms_public_key_der(kms_version_id):
    """Fetches the Public Key from KMS and returns it as DER bytes."""
    # request={"name": ...} MUST be a CryptoKeyVersion
    response = kms_client.get_public_key(request={"name": kms_version_id})
    
    pub_key = serialization.load_pem_public_key(response.pem.encode("utf-8"))
    return pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def get_matching_cert_chain(ca_pool_full_name, kms_version_id):
    """Finds the active certificate in the pool that MATCHES the KMS Key Version."""
    print(f"🔍 Fetching Public Key for Version: {kms_version_id.split('/')[-1]}...")
    target_pub_key_der = get_kms_public_key_der(kms_version_id)
    
    print(f"🔍 Searching CA Pool: {ca_pool_full_name}...")
    request = privateca_v1.ListCertificatesRequest(parent=ca_pool_full_name)
    
    candidates = [c for c in ca_client.list_certificates(request=request) 
                  if c.revocation_details.revocation_state != 2]
    
    for cert in candidates:
        cert_obj = x509.load_pem_x509_certificate(cert.pem_certificate.encode("utf-8"))
        cert_pub_der = cert_obj.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        if target_pub_key_der == cert_pub_der:
            print(f"✅ Found MATCHING Certificate: {cert.name}")
            chain_parts = [cert.pem_certificate.strip()]
            if cert.pem_certificate_chain:
                for part in cert.pem_certificate_chain:
                    chain_parts.append(part.strip())
            return "\n".join(chain_parts)

    raise RuntimeError(f"No active certificate found in pool that matches KMS Key: {kms_version_id}")

@functions_framework.cloud_event
def c2pa_sign_pubsub(cloud_event):
    data = cloud_event.data
    bucket_name = data.get("bucket")
    file_name = data.get("name")

    if not bucket_name or not file_name:
        return

    # Env Vars
    project_id = os.environ.get('PROJECT_ID')
    raw_kms_id = os.environ.get('KMS_KEY_ID') 
    ca_pool_id = os.environ.get('CA_POOL_ID') 
    signed_bucket_name = os.environ.get('SIGNED_BUCKET_NAME')
    
    if bucket_name == signed_bucket_name:
        print("Loop protection: Skipping.")
        return

    # Validate file type
    _, ext = os.path.splitext(file_name)
    ext = ext.lower()
    if ext not in SUPPORTED_MIME_TYPES:
        print(f"⚠️ Skipping unsupported file type: {file_name}")
        return
    target_mime_type = SUPPORTED_MIME_TYPES[ext]

    temp_input = f"/tmp/{file_name}"
    temp_output = f"/tmp/signed-{file_name}"

    try:
        print(f"🚀 Processing {file_name} ({target_mime_type})")
        
        # --- FIX: Resolve Key ID to Version ID ---
        kms_version_id = resolve_kms_version(raw_kms_id)
        # -----------------------------------------

        author_name = get_secret(project_id, os.environ.get('AUTHOR_NAME_SECRET_ID'))
        claim_generator = get_secret(project_id, os.environ.get('CLAIM_GENERATOR_SECRET_ID'))

        # 1. Download File
        storage_client.bucket(bucket_name).blob(file_name).download_to_filename(temp_input)

        # 2. Get the CERT that matches OUR KEY VERSION
        cert_chain_pem = get_matching_cert_chain(ca_pool_id, kms_version_id)

        # 3. Define the KMS Callback
        def kms_sign_callback(data: bytes) -> bytes:
            print(f"✍️ KMS Signing {len(data)} bytes with {kms_version_id.split('/')[-1]}...")
            digest = hashlib.sha256(data).digest()
            
            digest_crc32c = google_crc32c.Checksum()
            digest_crc32c.update(digest)
            crc32_int = int.from_bytes(digest_crc32c.digest(), byteorder="big")
            
            resp = kms_client.asymmetric_sign(
                request={
                    "name": kms_version_id, # Must be the Version ID
                    "digest": {"sha256": digest},
                    "digest_crc32c": crc32_int
                }
            )
            return der_to_raw_signature(resp.signature)

        # 4. Prepare Manifest
        manifest_definition = {
            "claim_generator": claim_generator,
            "format": target_mime_type,
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {"actions": [{"action": "c2pa.created"}]}
                },
                {
                    "label": "stds.schema-org.CreativeWork",
                    "data": {
                        "@context": "https://schema.org",
                        "author": [{"@type": "Person", "name": author_name}]
                    }
                }
            ]
        }
        
        print("🔐 Initializing Signer via Callback...")

        with c2pa.Signer.from_callback(
            callback=kms_sign_callback,
            alg=c2pa.C2paSigningAlg.ES256, 
            certs=cert_chain_pem,
        ) as signer:
            
            with c2pa.Builder(manifest_definition) as builder:
                builder.sign_file(
                    source_path=temp_input,
                    dest_path=temp_output,
                    signer=signer
                )

        print(f"✅ Signed. Uploading to {signed_bucket_name}...")
        
        dest_blob = storage_client.bucket(signed_bucket_name).blob(file_name)
        dest_blob.upload_from_filename(temp_output)

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if os.path.exists(temp_input): os.remove(temp_input)
        if os.path.exists(temp_output): os.remove(temp_output)

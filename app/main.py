# main.py
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from enum import Enum
import subprocess
import tempfile
import os
import uuid
import time
import shutil
import zipfile
import threading

app = FastAPI(
    title="OpenSSL Certificate Agent API",
    description="API for generating and managing SSL/TLS certificates",
    version="1.0.0"
)

# ============== CONFIGURATION ==============

# Base URL for download links - change this to your actual domain
BASE_URL = os.getenv("BASE_URL", "http://localhost:8025")

# How long to keep files (in seconds)
FILE_EXPIRY_SECONDS = 3600  # 1 hour

# Storage directory
STORAGE_DIR = "/tmp/cert-storage"
os.makedirs(STORAGE_DIR, exist_ok=True)

# ============== STORAGE MANAGEMENT ==============

# Simple in-memory tracking of stored files
stored_files: Dict[str, dict] = {}

def cleanup_expired_files():
    """Remove expired files periodically"""
    while True:
        time.sleep(300)  # Check every 5 minutes
        current_time = time.time()
        expired = [
            file_id for file_id, info in stored_files.items()
            if current_time > info["expires_at"]
        ]
        for file_id in expired:
            try:
                shutil.rmtree(os.path.join(STORAGE_DIR, file_id), ignore_errors=True)
                del stored_files[file_id]
            except:
                pass

# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_expired_files, daemon=True)
cleanup_thread.start()


def store_certificate_files(
    certificate: str = None,
    private_key: str = None,
    ca_certificate: str = None,
    csr: str = None,
    description: str = ""
) -> dict:
    """Store certificate files and return download info"""
    
    file_id = str(uuid.uuid4())
    file_dir = os.path.join(STORAGE_DIR, file_id)
    os.makedirs(file_dir, exist_ok=True)
    
    files_info = []
    
    # Save individual files
    if certificate:
        cert_path = os.path.join(file_dir, "certificate.crt")
        with open(cert_path, "w") as f:
            f.write(certificate)
        files_info.append({
            "name": "certificate.crt",
            "description": "SSL/TLS Certificate",
            "url": f"{BASE_URL}/download/{file_id}/certificate.crt"
        })
    
    if private_key:
        key_path = os.path.join(file_dir, "private.key")
        with open(key_path, "w") as f:
            f.write(private_key)
        files_info.append({
            "name": "private.key",
            "description": "Private Key (keep secure!)",
            "url": f"{BASE_URL}/download/{file_id}/private.key"
        })
    
    if ca_certificate:
        ca_path = os.path.join(file_dir, "ca.crt")
        with open(ca_path, "w") as f:
            f.write(ca_certificate)
        files_info.append({
            "name": "ca.crt",
            "description": "CA Certificate",
            "url": f"{BASE_URL}/download/{file_id}/ca.crt"
        })
    
    if csr:
        csr_path = os.path.join(file_dir, "request.csr")
        with open(csr_path, "w") as f:
            f.write(csr)
        files_info.append({
            "name": "request.csr",
            "description": "Certificate Signing Request",
            "url": f"{BASE_URL}/download/{file_id}/request.csr"
        })
    
    # Create ZIP bundle
    if len(files_info) > 0:
        zip_path = os.path.join(file_dir, "certificates.zip")
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_info in files_info:
                file_path = os.path.join(file_dir, file_info["name"])
                zipf.write(file_path, file_info["name"])
        files_info.append({
            "name": "certificates.zip",
            "description": "All files in ZIP archive",
            "url": f"{BASE_URL}/download/{file_id}/certificates.zip"
        })
    
    # Calculate expiry
    expires_at = time.time() + FILE_EXPIRY_SECONDS
    
    # Store metadata
    stored_files[file_id] = {
        "created_at": time.time(),
        "expires_at": expires_at,
        "description": description
    }
    
    return {
        "download_id": file_id,
        "files": files_info,
        "expires_in_seconds": FILE_EXPIRY_SECONDS,
        "expires_in_minutes": FILE_EXPIRY_SECONDS // 60
    }


# ============== ENUMS ==============

class KeyAlgorithm(str, Enum):
    RSA = "rsa"
    ECDSA = "ecdsa"

class KeySize(int, Enum):
    RSA_2048 = 2048
    RSA_4096 = 4096

class ECCurve(str, Enum):
    PRIME256V1 = "prime256v1"
    SECP384R1 = "secp384r1"
    SECP521R1 = "secp521r1"


# ============== REQUEST MODELS ==============

class SubjectInfo(BaseModel):
    common_name: str = Field(..., description="Domain name or entity name (CN)")
    organization: Optional[str] = Field(None, description="Organization name (O)")
    organizational_unit: Optional[str] = Field(None, description="Department (OU)")
    country: Optional[str] = Field(None, max_length=2, description="2-letter country code (C)")
    state: Optional[str] = Field(None, description="State or Province (ST)")
    locality: Optional[str] = Field(None, description="City (L)")
    email: Optional[str] = Field(None, description="Email address")

class GenerateKeyRequest(BaseModel):
    algorithm: KeyAlgorithm = KeyAlgorithm.RSA
    key_size: Optional[KeySize] = KeySize.RSA_2048
    ec_curve: Optional[ECCurve] = ECCurve.PRIME256V1

class CreateCSRRequest(BaseModel):
    private_key_download_id: Optional[str] = Field(None, description="Download ID from previous key generation")
    subject: SubjectInfo
    san_dns: Optional[List[str]] = Field(None, description="Subject Alternative Names - DNS")
    san_ip: Optional[List[str]] = Field(None, description="Subject Alternative Names - IP")

class SelfSignedCertRequest(BaseModel):
    subject: SubjectInfo
    algorithm: KeyAlgorithm = KeyAlgorithm.RSA
    key_size: Optional[KeySize] = KeySize.RSA_2048
    ec_curve: Optional[ECCurve] = ECCurve.PRIME256V1
    validity_days: int = Field(365, ge=1, le=3650)
    san_dns: Optional[List[str]] = None
    san_ip: Optional[List[str]] = None

class CreateCARequest(BaseModel):
    subject: SubjectInfo
    algorithm: KeyAlgorithm = KeyAlgorithm.RSA
    key_size: Optional[KeySize] = KeySize.RSA_4096
    validity_days: int = Field(3650, ge=365, le=7300)

class SignCSRRequest(BaseModel):
    csr_download_id: str = Field(..., description="Download ID of the CSR")
    ca_download_id: str = Field(..., description="Download ID of the CA certificate")
    validity_days: int = Field(365, ge=1, le=3650)


# ============== RESPONSE MODELS ==============

class FileInfo(BaseModel):
    name: str
    description: str
    url: str

class DownloadResponse(BaseModel):
    message: str
    download_id: str
    files: List[FileInfo]
    expires_in_minutes: int
    instructions: Optional[str] = None


# ============== HELPER FUNCTIONS ==============

def build_subject_string(subject: SubjectInfo) -> str:
    parts = []
    if subject.country:
        parts.append(f"/C={subject.country}")
    if subject.state:
        parts.append(f"/ST={subject.state}")
    if subject.locality:
        parts.append(f"/L={subject.locality}")
    if subject.organization:
        parts.append(f"/O={subject.organization}")
    if subject.organizational_unit:
        parts.append(f"/OU={subject.organizational_unit}")
    parts.append(f"/CN={subject.common_name}")
    if subject.email:
        parts.append(f"/emailAddress={subject.email}")
    return "".join(parts)

def run_openssl(args: List[str], input_data: str = None) -> tuple:
    try:
        result = subprocess.run(
            ["openssl"] + args,
            input=input_data.encode() if input_data else None,
            capture_output=True,
            timeout=30
        )
        return result.stdout.decode(), result.stderr.decode(), result.returncode
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="OpenSSL command timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OpenSSL error: {str(e)}")


# ============== DOWNLOAD ENDPOINT ==============

@app.get("/download/{file_id}/{filename}")
async def download_file(file_id: str, filename: str):
    """Download a generated certificate file"""
    
    # Check if file exists and not expired
    if file_id not in stored_files:
        raise HTTPException(status_code=404, detail="File not found or expired")
    
    if time.time() > stored_files[file_id]["expires_at"]:
        raise HTTPException(status_code=410, detail="File has expired")
    
    file_path = os.path.join(STORAGE_DIR, file_id, filename)
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    # Determine content type
    content_types = {
        ".crt": "application/x-x509-ca-cert",
        ".key": "application/x-pem-file",
        ".pem": "application/x-pem-file",
        ".csr": "application/pkcs10",
        ".zip": "application/zip"
    }
    
    ext = os.path.splitext(filename)[1]
    content_type = content_types.get(ext, "application/octet-stream")
    
    return FileResponse(
        path=file_path,
        filename=filename,
        media_type=content_type
    )


# ============== API ENDPOINTS ==============

@app.post("/api/v1/keys/generate", response_model=DownloadResponse)
async def generate_key(request: GenerateKeyRequest):
    """Generate a new private/public key pair"""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        key_file = os.path.join(tmpdir, "private.key")
        pub_file = os.path.join(tmpdir, "public.key")
        
        # Generate private key
        if request.algorithm == KeyAlgorithm.RSA:
            args = ["genrsa", "-out", key_file, str(request.key_size.value)]
            key_info = f"RSA {request.key_size.value}-bit"
        else:
            args = ["ecparam", "-genkey", "-name", request.ec_curve.value, "-out", key_file]
            key_info = f"ECDSA {request.ec_curve.value}"
        
        stdout, stderr, code = run_openssl(args)
        if code != 0:
            raise HTTPException(status_code=500, detail=f"Key generation failed: {stderr}")
        
        # Extract public key
        run_openssl(["pkey", "-in", key_file, "-pubout", "-out", pub_file])
        
        with open(key_file, "r") as f:
            private_key = f.read()
        
        # Store and get download links
        download_info = store_certificate_files(
            private_key=private_key,
            description=f"{key_info} key pair"
        )
        
        return DownloadResponse(
            message=f"Generated {key_info} key pair",
            download_id=download_info["download_id"],
            files=[FileInfo(**f) for f in download_info["files"]],
            expires_in_minutes=download_info["expires_in_minutes"],
            instructions="Keep your private key secure and never share it!"
        )


@app.post("/api/v1/certificates/self-signed", response_model=DownloadResponse)
async def create_self_signed_certificate(request: SelfSignedCertRequest):
    """Create a self-signed certificate"""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        key_file = os.path.join(tmpdir, "private.key")
        cert_file = os.path.join(tmpdir, "certificate.crt")
        config_file = os.path.join(tmpdir, "openssl.cnf")
        
        # Generate key
        if request.algorithm == KeyAlgorithm.RSA:
            key_args = ["genrsa", "-out", key_file, str(request.key_size.value)]
        else:
            key_args = ["ecparam", "-genkey", "-name", request.ec_curve.value, "-out", key_file]
        
        run_openssl(key_args)
        
        subject = build_subject_string(request.subject)
        
        # Create config
        config_content = f"""
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
CN = {request.subject.common_name}

[v3_ca]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
"""
        
        if request.san_dns or request.san_ip:
            san_parts = []
            if request.san_dns:
                san_parts.extend([f"DNS:{dns}" for dns in request.san_dns])
            if request.san_ip:
                san_parts.extend([f"IP:{ip}" for ip in request.san_ip])
            config_content += f"subjectAltName = {','.join(san_parts)}\n"
        
        with open(config_file, "w") as f:
            f.write(config_content)
        
        # Generate certificate
        cert_args = [
            "req", "-new", "-x509", "-key", key_file, "-out", cert_file,
            "-days", str(request.validity_days), "-subj", subject,
            "-config", config_file
        ]
        
        stdout, stderr, code = run_openssl(cert_args)
        if code != 0:
            raise HTTPException(status_code=500, detail=f"Certificate creation failed: {stderr}")
        
        with open(key_file, "r") as f:
            private_key = f.read()
        with open(cert_file, "r") as f:
            certificate = f.read()
        
        # Store and get download links
        download_info = store_certificate_files(
            certificate=certificate,
            private_key=private_key,
            description=f"Self-signed certificate for {request.subject.common_name}"
        )
        
        return DownloadResponse(
            message=f"Created self-signed certificate for {request.subject.common_name}",
            download_id=download_info["download_id"],
            files=[FileInfo(**f) for f in download_info["files"]],
            expires_in_minutes=download_info["expires_in_minutes"],
            instructions=f"Certificate valid for {request.validity_days} days. Add to your server configuration."
        )


@app.post("/api/v1/certificates/ca", response_model=DownloadResponse)
async def create_ca_certificate(request: CreateCARequest):
    """Create a Certificate Authority certificate"""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        key_file = os.path.join(tmpdir, "ca.key")
        cert_file = os.path.join(tmpdir, "ca.crt")
        config_file = os.path.join(tmpdir, "openssl.cnf")
        
        # Generate CA key
        if request.algorithm == KeyAlgorithm.RSA:
            key_args = ["genrsa", "-out", key_file, str(request.key_size.value)]
        else:
            key_args = ["ecparam", "-genkey", "-name", "secp384r1", "-out", key_file]
        
        run_openssl(key_args)
        
        subject = build_subject_string(request.subject)
        
        config_content = f"""
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
CN = {request.subject.common_name}

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer:always
"""
        
        with open(config_file, "w") as f:
            f.write(config_content)
        
        cert_args = [
            "req", "-new", "-x509", "-key", key_file, "-out", cert_file,
            "-days", str(request.validity_days), "-subj", subject,
            "-config", config_file
        ]
        
        stdout, stderr, code = run_openssl(cert_args)
        if code != 0:
            raise HTTPException(status_code=500, detail=f"CA creation failed: {stderr}")
        
        with open(key_file, "r") as f:
            private_key = f.read()
        with open(cert_file, "r") as f:
            certificate = f.read()
        
        download_info = store_certificate_files(
            certificate=certificate,
            private_key=private_key,
            description=f"CA Certificate: {request.subject.common_name}"
        )
        
        return DownloadResponse(
            message=f"Created CA certificate: {request.subject.common_name}",
            download_id=download_info["download_id"],
            files=[FileInfo(**f) for f in download_info["files"]],
            expires_in_minutes=download_info["expires_in_minutes"],
            instructions="This is your Certificate Authority. Keep the private key extremely secure! Distribute ca.crt to systems that need to trust certificates signed by this CA."
        )


@app.post("/api/v1/csr/create", response_model=DownloadResponse)
async def create_csr(request: CreateCSRRequest):
    """Create a Certificate Signing Request"""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        key_file = os.path.join(tmpdir, "private.key")
        csr_file = os.path.join(tmpdir, "request.csr")
        config_file = os.path.join(tmpdir, "openssl.cnf")
        
        # If using existing key from previous generation
        if request.private_key_download_id:
            stored_key_path = os.path.join(STORAGE_DIR, request.private_key_download_id, "private.key")
            if not os.path.exists(stored_key_path):
                raise HTTPException(status_code=404, detail="Private key not found. Generate a new key first.")
            shutil.copy(stored_key_path, key_file)
        else:
            # Generate new key
            run_openssl(["genrsa", "-out", key_file, "2048"])
        
        subject = build_subject_string(request.subject)
        
        config_content = f"""
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = {request.subject.common_name}

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
"""
        
        if request.san_dns or request.san_ip:
            san_parts = []
            if request.san_dns:
                san_parts.extend([f"DNS:{dns}" for dns in request.san_dns])
            if request.san_ip:
                san_parts.extend([f"IP:{ip}" for ip in request.san_ip])
            config_content += f"subjectAltName = {','.join(san_parts)}\n"
        
        with open(config_file, "w") as f:
            f.write(config_content)
        
        args = [
            "req", "-new", "-key", key_file, "-out", csr_file,
            "-subj", subject, "-config", config_file
        ]
        
        stdout, stderr, code = run_openssl(args)
        if code != 0:
            raise HTTPException(status_code=500, detail=f"CSR creation failed: {stderr}")
        
        with open(key_file, "r") as f:
            private_key = f.read()
        with open(csr_file, "r") as f:
            csr = f.read()
        
        download_info = store_certificate_files(
            csr=csr,
            private_key=private_key,
            description=f"CSR for {request.subject.common_name}"
        )
        
        return DownloadResponse(
            message=f"Created CSR for {request.subject.common_name}",
            download_id=download_info["download_id"],
            files=[FileInfo(**f) for f in download_info["files"]],
            expires_in_minutes=download_info["expires_in_minutes"],
            instructions="Submit the .csr file to your Certificate Authority. Keep the private key secure - you'll need it when you receive the signed certificate."
        )


@app.post("/api/v1/certificates/sign", response_model=DownloadResponse)
async def sign_certificate(request: SignCSRRequest):
    """Sign a CSR with a CA certificate"""
    
    # Get CSR from storage
    csr_path = os.path.join(STORAGE_DIR, request.csr_download_id, "request.csr")
    if not os.path.exists(csr_path):
        raise HTTPException(status_code=404, detail="CSR not found")
    
    # Get CA files from storage
    ca_cert_path = os.path.join(STORAGE_DIR, request.ca_download_id, "certificate.crt")
    ca_key_path = os.path.join(STORAGE_DIR, request.ca_download_id, "private.key")
    
    if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
        raise HTTPException(status_code=404, detail="CA certificate or key not found")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_file = os.path.join(tmpdir, "signed.crt")
        config_file = os.path.join(tmpdir, "openssl.cnf")
        
        config_content = """
[v3_ext]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
"""
        
        with open(config_file, "w") as f:
            f.write(config_content)
        
        sign_args = [
            "x509", "-req", "-in", csr_path,
            "-CA", ca_cert_path, "-CAkey", ca_key_path,
            "-CAcreateserial", "-out", cert_file,
            "-days", str(request.validity_days),
            "-extfile", config_file, "-extensions", "v3_ext"
        ]
        
        stdout, stderr, code = run_openssl(sign_args)
        if code != 0:
            raise HTTPException(status_code=500, detail=f"Signing failed: {stderr}")
        
        with open(cert_file, "r") as f:
            certificate = f.read()
        with open(ca_cert_path, "r") as f:
            ca_certificate = f.read()
        
        download_info = store_certificate_files(
            certificate=certificate,
            ca_certificate=ca_certificate,
            description="Signed certificate"
        )
        
        return DownloadResponse(
            message="Certificate signed successfully",
            download_id=download_info["download_id"],
            files=[FileInfo(**f) for f in download_info["files"]],
            expires_in_minutes=download_info["expires_in_minutes"],
            instructions=f"Certificate valid for {request.validity_days} days. Use with the private key from your original CSR."
        )


# Health check
@app.get("/health")
async def health_check():
    stdout, stderr, code = run_openssl(["version"])
    if code == 0:
        return {"status": "healthy", "openssl_version": stdout.strip()}
    return {"status": "unhealthy", "error": stderr}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8025)

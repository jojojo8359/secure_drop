from filenames import CA_CERT_FILE, CA_KEY_FILE
from typing import Union
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
import datetime

CA_CN = "g4_secure_drop"

def gen_ca():
    """
    Generate new CA files on disk (private key: \"ca.key\" & certificate: \"ca.cert\").
    The certificate is valid for 30 days.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(CA_KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # Since we're self-signing, subject = issuer
    subject = issuer = x509.Name([
        # The only field we really care about here is a unique CA name
        x509.NameAttribute(NameOID.COMMON_NAME, CA_CN)
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Sign the certificate for 30 days
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
    ).add_extension(
        # Add a Subject Key Identifier and Authority Key Identifier, since a CA certificate can be re-generated with the same CN
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
        critical=False
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    ).sign(key, hashes.SHA256(), rsa_padding=padding.PKCS1v15())
    with open(CA_CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def build_csr(private_key: ec.EllipticCurvePrivateKey, email: str) -> x509.CertificateSigningRequest:
    """
    Build a Certificate Signing Request from an EC private key and a user's email.
    """
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, email),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    ).sign(private_key, hashes.SHA256())
    return csr


def load_ca_key() -> Union[rsa.RSAPrivateKey, None]:
    """
    Load the CA's key from disk.
    
    If the key isn't an RSA private key, returns None. Otherwise, returns the RSA private key.
    """
    with open(CA_KEY_FILE, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(), password=None
        )
    if isinstance(ca_key, rsa.RSAPrivateKey):
        return ca_key
    return None


def load_ca_cert() -> x509.Certificate:
    """
    Load the CA's certificate from disk. Does not verify the certificate - use verify_ca_cert().
    """
    with open(CA_CERT_FILE, "rb") as f:
        ca_cert_pem = f.read()
    return x509.load_pem_x509_certificate(ca_cert_pem)


def verify_ca_cert(ca_cert: x509.Certificate) -> bool:
    """
    Verify that the CA's certificate is valid.
    
    Checks that:
    - The cert is self-signed
    - The cert has a supported public key type
    - The cert has a valid signature
    - The cert is valid (not expired and active)
    - The cert is a CA cert (can issue certificates)
    - The cert has an expected CN (issuer and subject)
    - The cert matches the private CA key on disk
    
    If all these checks pass, returns True. Otherwise, returns False.
    """
    # Check if the CA certificate is self-signed and has a valid signature
    try:
        ca_cert.verify_directly_issued_by(ca_cert)
    except ValueError:
        print("CA: The CA certificate is not self-signed.")
        return False
    except TypeError:
        print("CA: The CA certificate does not have a supported public key type.")
        return False
    except InvalidSignature:
        print("CA: Couldn't verify the CA certificate's signature.")
        return False
    # Check if CA certificate is still valid
    if datetime.datetime.now(datetime.timezone.utc) >= ca_cert.not_valid_after_utc:
        print("CA: CA certificate has expired.")
        return False
    if datetime.datetime.now(datetime.timezone.utc) <= ca_cert.not_valid_before_utc:
        print("CA: CA certificate is not yet active.")
        return False
    # Check if CA can issue certificates
    basic_constraints = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    if basic_constraints.value.ca != True:
        print("CA: CA cannot issue certificates.")
        return False
    # Check if CA has expected name (for issuer and subject both)
    issuer_common_names = ca_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(issuer_common_names) != 1:
        print("CA: CA does not have exactly one issuer common name.")
        return False
    if issuer_common_names[0].value != CA_CN:
        print("CA: CA issuer common name was unexpected.")
        return False
    subject_common_names = ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(subject_common_names) != 1:
        print("CA: CA does not have exactly one subject common name.")
        return False
    if subject_common_names[0].value != CA_CN:
        print("CA: CA subject common name was unexpected.")
        return False
    ca_key = load_ca_key()
    if ca_key == None:
        print("CA: Couldn't load CA private key for CA verification.")
        return None
    ca_public_key = ca_key.public_key()
    try:
        ca_public_key.verify(
            ca_cert.signature,
            ca_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            ca_cert.signature_hash_algorithm
        )
    except InvalidSignature:
        print("CA: Couldn't validate certificate with CA key.")
        return False
    return True


def verify_csr(csr: x509.CertificateSigningRequest) -> bool:
    """
    Verify if a CSR: has one CN, has one email, and the CN and email match.
    
    If all these checks pass, returns True. Otherwise, returns False.
    """
    subject_common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(subject_common_names) != 1:
        print("CA: CSR does not have exactly one subject common name.")
        return False
    subject_emails = csr.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
    if len(subject_emails) != 1:
        print("CA: CSR does not have exactly one subject email address.")
        return False
    if subject_common_names[0].value != subject_emails[0].value:
        print("CA: CSR has mismatching common name and email address.")
        return False
    return True


def sign_csr(csr: x509.CertificateSigningRequest) -> Union[x509.Certificate, None]:
    """
    Create a certificate signed by the CA from a CSR.
    
    If a check fails, returns None. Otherwise, the signed certificate is returned.
    """
    ### LOAD AND VERIFY CA CERTIFICATE
    ca_cert = load_ca_cert()
    if not verify_ca_cert(ca_cert):
        print("CA: Couldn't verify CA certificate.")
        return None
    
    ### VERIFY CSR
    if not verify_csr(csr):
        return None
    
    # Load the CA's private key to sign with
    ca_key = load_ca_key()
    if ca_key == None:
        print("CA: Couldn't load CA private key for signing.")
        return None
    
    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Have certificate be valid for 5 minutes
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
    ).sign(ca_key, hashes.SHA256(), rsa_padding=padding.PKCS1v15())
    return cert


def validate_cert(cert: x509.Certificate, email: str) -> bool:
    """
    Validates a certificate by:
    - Checking if it's signed by the CA (based on cert and key)
    - Checking if it's still valid (not expired and active)
    - Checking if it has a valid identity and it matches the expected email (from the parameter)
    
    If all these checks pass, returns True. Otherwise, returns False.
    """
    ca_cert = load_ca_cert()
    if not verify_ca_cert(ca_cert):
        print("CA: Couldn't verify CA certificate.")
        return False
    ca_key = load_ca_key()
    if ca_key == None:
        print("CA: Couldn't load CA private key for validation.")
        return False
    ca_public_key = ca_key.public_key()
    try:
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    except InvalidSignature:
        print("CA: Couldn't validate certificate with CA key.")
        return False
    try:
        cert.verify_directly_issued_by(ca_cert)
    except ValueError:
        print("CA: The certificate was not signed by the CA.")
        return False
    except TypeError:
        print("CA: The certificate does not have a supported public key type.")
        return False
    except InvalidSignature:
        print("CA: Couldn't verify the certificate's signature.")
        return False
    if datetime.datetime.now(datetime.timezone.utc) >= cert.not_valid_after_utc:
        print("CA: Certificate has expired.")
        return False
    if datetime.datetime.now(datetime.timezone.utc) <= cert.not_valid_before_utc:
        print("CA: Certificate is not yet active.")
        return False
    subject_common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(subject_common_names) != 1:
        print("CA: Certificate does not have exactly one subject common name.")
        return False
    subject_emails = cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
    if len(subject_emails) != 1:
        print("CA: Certificate does not have exactly one subject email address.")
        return False
    if subject_common_names[0].value != subject_emails[0].value:
        print("CA: Certificate has mismatching common name and email address.")
        return False
    if subject_common_names[0].value != email and subject_emails[0].value != email:
        print("CA: Certificate does not belong to expected user (email unexpected).")
        return False
    return True

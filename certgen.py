from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime


class AutoCertGen:
    def __init__(self):
        pass

    def gen_cert():
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Define subject and issuer (self-signed)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "ZZ"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Some province"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Some place"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Some org"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ]
        )

        # Create certificate
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            )  # 1 year validity
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
            )
            .sign(private_key, hashes.SHA256())
        )

        # Save private key
        with open("key.pem", "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Save certificate
        with open("certificate.pem", "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

        print("Self-signed certificate and private key generated for HTTPS server!")

import socket
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

host = "localhost"
port = 5550

def generate_ca_certificate():
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KPI"),
        x509.NameAttribute(NameOID.COMMON_NAME, "main"),
    ])

    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.today() + datetime.timedelta(days=365))
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )

    return ca_private_key, ca_certificate

# Генерація сертифіката для сервера
def generate_server_certificate(public_server_key, ca_private_key, ca_certificate):
    public_server_key = serialization.load_pem_public_key(public_server_key)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KPI"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(public_server_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.today())
        .not_valid_after(datetime.datetime.today() + datetime.timedelta(days=365))
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )

    return server_certificate

# Верифікація сертифіката
def verify_certificate(client_cert, ca_certificate):
    try:
        ca_certificate.public_key().verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification error: {e}")
        return False

def run_ca_server():
    ca_private_key, ca_certificate = generate_ca_certificate()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"CA server started on {host}:{port}")

    while True:
        conn, _ = server_socket.accept()

        request_type, data = conn.recv(4096).split(b"\n", 1)

        if request_type.decode() == "SERVER_REQUEST":
            print(f"Request certificate from server")
            server_certificate = generate_server_certificate(data, ca_private_key, ca_certificate)
            conn.send(server_certificate.public_bytes(serialization.Encoding.PEM))
            print("Certificate was generated")

        elif request_type.decode() == "CLIENT_VERIFY":
            print(f"Request for certificate verification")
            # Отримання сертифіката від клієнта
            client_cert = x509.load_pem_x509_certificate(data)

            # Верифікація отриманого сертифіката
            is_valid = verify_certificate(client_cert, ca_certificate)
            if is_valid:
                conn.send(b"VALID")
                print("Certificate is valid")
            else:
                conn.send(b"INVALID")
                print("Certificate invalid")

        conn.close()

if __name__ == "__main__":
    run_ca_server()

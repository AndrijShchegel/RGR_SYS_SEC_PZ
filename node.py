import os
import sys
import time
import socket
import threading
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509 import load_pem_x509_certificate

class Node:
    def __init__(self, host, port, ca_port):
        self.host = host
        self.port = port
        self.ca_port = ca_port
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.connections = {}
        self.running = True

    def start(self):
        server_thread = threading.Thread(target=self.run_server)
        server_thread.start()
        time.sleep(0.5)
        self.run_client_interface()

    def run_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen(5)
        server.settimeout(1)
        print(f"Node listening on {self.host}:{self.port}")

        while self.running:
            try:
                connection, _ = server.accept()
                threading.Thread(target=self.handle_connection, args=(connection,)).start()
            except socket.timeout:
                continue
            except OSError as e:
                if not self.running:
                    break
                print(f"Server error: {e}")

        server.close()

    def handle_connection(self, connection):
        try:
            client_hello = connection.recv(1024)
            client_random = client_hello[-16:]
            client_hello_message = client_hello[:-16].decode()
            client_port = None
            if "from" in client_hello_message:
                client_port = int(client_hello_message.split("from")[1].strip())
            print(f"\nNew connection from {connection.getpeername()} (origin port: {client_port})")

            server_random = os.urandom(16)
            server_hello = b"Server hello" + server_random
            server_cert = self.get_certificate()
            connection.send(server_hello)
            connection.send(server_cert)
            print(f"Sent hello")

            encrypted_premaster = connection.recv(1024)
            premaster = self.decrypt_premaster(encrypted_premaster)
            print(f"Received premaster")

            session_key = self.generate_session_key(client_random, server_random, premaster)
            print("Session key established")

            server_ready = self.encrypt_message(session_key, "Ready")
            connection.send(server_ready)

            client_ready = connection.recv(1024)
            client_ready = self.decrypt_message(session_key, client_ready).decode()

            if client_ready != "Ready":
                raise Exception("Session keys mismatch")

            peer_address = connection.getpeername()
            self.connections[peer_address] = (connection, session_key)

            while self.running:
                encrypted_msg = connection.recv(1024)
                if not encrypted_msg:
                    break

                msg = self.decrypt_message(session_key, encrypted_msg).decode()
                print(f"\nMessage from {peer_address}: {msg}")

                response = f"Received: {msg}"
                encrypted_response = self.encrypt_message(session_key, response)
                connection.send(encrypted_response)

        except Exception as e:
            print(f"Connection error: {e}")
        finally:
            connection.close()
            if peer_address in self.connections:
                del self.connections[peer_address]

    def connect_to_node(self, target_host, target_port):
        try:
            if (target_host, target_port) in self.connections:
                print(f"Already connected to {target_host}:{target_port}")
                return

            node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            node.connect((target_host, target_port))

            node_random = os.urandom(16)
            node_hello = f"Client hello from {self.port}".encode() + node_random
            node.send(node_hello)

            server_hello = node.recv(1024)
            server_random = server_hello[-16:]
            server_cert = node.recv(2048)
            cert = load_pem_x509_certificate(server_cert)

            if not self.verify_certificate(cert):
                raise Exception("Certificate verification failed")

            premaster = os.urandom(16)
            encrypted_premaster = cert.public_key().encrypt(
                premaster,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                           algorithm=hashes.SHA256(), 
                           label=None)
            )
            node.send(encrypted_premaster)

            session_key = self.generate_session_key(node_random, server_random, premaster)

            server_ready = node.recv(1024)
            server_ready = self.decrypt_message(session_key, server_ready).decode()

            if server_ready != "Ready":
                raise Exception("Session keys mismatch")

            node_ready = self.encrypt_message(session_key, "Ready")
            node.send(node_ready)

            self.connections[(target_host, target_port)] = (node, session_key)
            print(f"Successfully connected to {target_host}:{target_port}")

            threading.Thread(target=self.listen_for_responses, 
                           args=(node, session_key, (target_host, target_port))).start()

        except Exception as e:
            print(f"Failed to connect to {target_host}:{target_port}: {e}")
            if node:
                node.close()

    def listen_for_responses(self, connection, session_key, peer_address):
        try:
            while self.running:
                response = connection.recv(1024)
                if not response:
                    break
                decrypted = self.decrypt_message(session_key, response).decode()
                print(f"\nResponse from {peer_address}: {decrypted}")
        except:
            pass
        finally:
            connection.close()
            if peer_address in self.connections:
                del self.connections[peer_address]

    def send_message(self, target_host, target_port, message):
        if (target_host, target_port) not in self.connections:
            print(f"Not connected to {target_host}:{target_port}")
            return

        connection, session_key = self.connections[(target_host, target_port)]
        try:
            encrypted = self.encrypt_message(session_key, message)
            connection.send(encrypted)
        except Exception as e:
            print(f"Failed to send message: {e}")

    def run_client_interface(self):
        print("\nAvailable commands:")
        print("connect <host> <port> - Connect to another node")
        print("send <host> <port> <message> - Send message to node")
        print("list - Show active connections")
        print("exit - Shutdown the node")

        while self.running:
            try:
                command = input("\nEnter command: ").strip().split()
                if not self.running:
                    break

                if command[0] == "connect" and len(command) == 3:
                    host = command[1]
                    port = int(command[2])
                    self.connect_to_node(host, port)

                elif command[0] == "send" and len(command) >= 4:
                    host = command[1]
                    port = int(command[2])
                    message = " ".join(command[3:])
                    self.send_message(host, port, message)

                elif command[0] == "list":
                    print("\nActive connections:")
                    for i, (host, port) in enumerate(self.connections.keys(), 1):
                        print(f"{i}. {host}:{port}")

                elif command[0] == "exit":
                    self.running = False
                    for conn, _ in self.connections.values():
                        conn.close()
                    
                    break

                else:
                    print("Unknown command")

            except Exception as e:
                print(f"Error: {e}")

    def encrypt_message(self, session_key, message):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        return iv + encryptor.update(message.encode()) + encryptor.finalize()

    def decrypt_message(self, session_key, message):
        iv = message[:16]
        cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(message[16:]) + decryptor.finalize()

    def generate_session_key(self, client_random, server_random, premaster):
        kdf = ConcatKDFHash(
            algorithm=hashes.SHA256(),
            length=32,
            otherinfo=client_random + server_random
        )
        return kdf.derive(premaster)

    def decrypt_premaster(self, encrypted_premaster):
        return self.private_key.decrypt(
            encrypted_premaster,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def get_certificate(self):
        ca_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ca_socket.connect((self.host, self.ca_port))
        ca_socket.send("SERVER_REQUEST".encode() + b"\n" +
                    self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo))
        cert = ca_socket.recv(4096)
        ca_socket.close()
        return cert

    def verify_certificate(self, cert):
        ca_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ca_socket.connect((self.host, self.ca_port))
        ca_socket.send("CLIENT_VERIFY".encode() + b"\n" + 
                      cert.public_bytes(serialization.Encoding.PEM))
        response = ca_socket.recv(4096).decode()
        ca_socket.close()
        return response == "VALID"

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python node.py <host> <port> <ca_port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    ca_port = int(sys.argv[3])

    node = Node(host, port, ca_port)
    node.start()

import socket
import pickle
import struct
from kyber import Kyber512

def send_message(sock, message):
    message = pickle.dumps(message)
    message = struct.pack('>I', len(message)) + message
    sock.sendall(message)

def receive_message(sock):
    raw_msglen = receive_all(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return pickle.loads(receive_all(sock, msglen))

def receive_all(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def main():
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(('localhost', 12345))
        print("Connected to the server.")

        try:
            kyber = Kyber512()

            # Receive the public key
            public_key = receive_message(client_socket)
            print("Received public key from the server.")

            # Encrypt to generate ciphertext and shared key
            ciphertext, shared_key = kyber.ccakem_encrypt(public_key)
            print("Shared key established successfully.")

            # Send the ciphertext
            send_message(client_socket, ciphertext)
            print("Sent ciphertext to the server.")
            print(f"Shared key: {shared_key}")

            print("Continue to use the shared key to encrypt/decrypt messages using AES...")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

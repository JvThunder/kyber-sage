import socket
import pickle
import struct
from kyber import Kyber512

def send_message(conn, message):
    message = pickle.dumps(message)
    message = struct.pack('>I', len(message)) + message
    conn.sendall(message)

def receive_message(conn):
    raw_msglen = receive_all(conn, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return pickle.loads(receive_all(conn, msglen))

def receive_all(conn, n):
    data = b''
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('localhost', 12345))
        server_socket.listen()

        print("Server is listening on port 12345")
        conn, addr = server_socket.accept()
        with conn:
            print(f'Connected by {addr}')
            try:
                kyber = Kyber512()
                public_key, secret_key = kyber.ccakem_generate_key()
                
                # Send the public key
                send_message(conn, public_key)
                print("Sent public key to the client.")

                # Receive the ciphertext
                ciphertext = receive_message(conn)
                print("Received ciphertext from the client.")

                # Decrypt the ciphertext
                shared_key = kyber.ccakem_decrypt(ciphertext, secret_key)
                print("Shared key established successfully.")
                print(f"Shared key: {shared_key}")

                print("Continue to use the shared key to encrypt/decrypt messages using AES...")
            except Exception as e:
                print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

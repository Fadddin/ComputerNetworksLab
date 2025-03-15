import socket
import threading

HOST = "127.0.0.1"
DEFAULT_PORT = 8888
POLYNOMIAL = 0b1101  # Example CRC polynomial


def crc_remainder(input_bitstring, polynomial):
    """ Compute CRC remainder using binary division """
    input_padded = input_bitstring + "0" * (len(bin(polynomial)) - 3)
    divisor = polynomial
    
    dividend = int(input_padded, 2)
    divisor = int(bin(divisor)[2:], 2)
    
    while dividend.bit_length() >= divisor.bit_length():
        shift = dividend.bit_length() - divisor.bit_length()
        dividend ^= divisor << shift
    
    return bin(dividend)[2:].zfill(len(bin(polynomial)) - 3)


def encode_message(message):
    """ Encode text to binary format with CRC error detection. """
    binary_message = " ".join(format(ord(char), "08b") for char in message)
    crc = crc_remainder(binary_message.replace(" ", ""), POLYNOMIAL)
    return f"0 {binary_message} {crc} 1"


def decode_message(binary_message):
    """ Decode binary format back to text and check CRC. """
    try:
        parts = binary_message.split()
        if not (parts[0] == "0" and parts[-1] == "1"):
            return "[ERROR] Invalid Message Format"
        
        binary_data = "".join(parts[1:-2])
        received_crc = parts[-2]
        calculated_crc = crc_remainder(binary_data, POLYNOMIAL)
        
        if received_crc != calculated_crc:
            return "[ERROR] CRC Check Failed"
        
        characters = [chr(int(b, 2)) for b in binary_data.split()]
        return "".join(characters)
    except Exception as e:
        return f"[ERROR] Decoding Failed: {e}"


def receiver(conn):
    """ Receives messages and decodes them. """
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                break
            decoded_message = decode_message(data.decode().strip())
            print(f"\nReceived: {decoded_message}\n> ", end="")
        except Exception as e:
            print(f"[ERROR] Receiver Error: {e}")
            break


def transmitter(sock):
    """ Sends messages after encoding. """
    while True:
        message = input("> ")
        if message.lower() == "exit":
            break
        encoded_message = encode_message(message)
        sock.sendall(encoded_message.encode() + b"\n")
    
    sock.close()
    print("Connection closed.")


def start_server():
    """ Starts the server to listen for incoming connections. """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, DEFAULT_PORT))
        server.listen()
        print(f"Listening on {HOST}:{DEFAULT_PORT}")
        conn, _ = server.accept()
        
        threading.Thread(target=receiver, args=(conn,)).start()
        transmitter(conn)


def start_client():
    """ Connects to the server as a client. """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, DEFAULT_PORT))
        print(f"Connected to {HOST}:{DEFAULT_PORT}")
        
        threading.Thread(target=receiver, args=(sock,)).start()
        transmitter(sock)


if __name__ == "__main__":
    mode = input("Start as server (s) or client (c)? ").strip().lower()
    if mode == "s":
        start_server()
    elif mode == "c":
        start_client()
    else:
        print("Invalid choice. Exiting.")

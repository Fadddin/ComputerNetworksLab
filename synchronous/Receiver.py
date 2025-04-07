import socket

HOST = '127.0.0.1'
PORT = 8888

def compute_parity(bits):
    return sum(bits) % 2

def receiver():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server started at {HOST}:{PORT}")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            buffer = []
            received_string = ""

            while True:
                bit = conn.recv(1)  # Receive one byte (a single bit as str)
                if not bit:
                    break  # connection closed
                try:
                    bit = int(bit.decode())
                except:
                    continue  # skip invalid data

                buffer.append(bit)

                # A frame = 1 start bit + 8 data bits + 1 parity + 1 stop = 11 bits
                if len(buffer) == 11:
                    start_bit, data_bits, parity_bit, stop_bit = buffer[0], buffer[1:9], buffer[9], buffer[10]

                    if start_bit == 1 and stop_bit == 0:
                        if compute_parity(data_bits) == parity_bit:
                            char = chr(int("".join(map(str, data_bits)), 2))
                            received_string += char
                        else:
                            print("Parity error detected!")
                    else:
                        print("Invalid frame structure")

                    buffer = []  # Reset for next frame

            print(f"\nFinal Received Message: {received_string}")

if __name__ == "__main__":
    while True:
        receiver()

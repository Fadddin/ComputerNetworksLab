import asyncio
import socket

HOST = "127.0.0.1"
DEFAULT_PORT = 8888

def encode_message(message):
    """ Encode text to binary format enclosed with start(0) and end(1) bits. """
    binary_message = " ".join(format(ord(char), "08b") for char in message)
    return f"0 {binary_message} 1"

def decode_message(binary_message):
    """ Decode binary format back to text. """
    try:
        if not (binary_message.startswith("0 ") and binary_message.endswith(" 1")):
            return "[ERROR] Invalid Message Format"
        
        binary_message = binary_message[2:-2]
        characters = [chr(int(b, 2)) for b in binary_message.split()]
        return "".join(characters)
    except Exception as e:
        return f"[ERROR] Decoding Failed: {e}"

async def handle_receiver(reader):
    """ Continuously receives messages and decodes them. """
    while True:
        data = await reader.read(1024)
        message = data.decode().strip()
        if not message:
            break
        decoded_message = decode_message(message)
        print(f"\nReceived: {decoded_message}\n> ", end="")

async def handle_transmitter(writer):
    """ Continuously sends messages after encoding. """
    while True:
        message = await asyncio.to_thread(input, "> ")
        if message.lower() == "exit":
            break
        encoded_message = encode_message(message)
        writer.write(encoded_message.encode() + b"\n")
        await writer.drain()

    writer.close()
    await writer.wait_closed()
    print("Connection closed.")

async def find_available_port(starting_port):
    """ Find an available port dynamically. """
    port = starting_port
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex((HOST, port)) != 0:
                return port
        port += 1

async def start_transceiver():
    """ Starts the bidirectional transceiver. """
    try:
        server = await asyncio.start_server(lambda r, w: asyncio.create_task(handle_receiver(r)), HOST, DEFAULT_PORT)
        port = DEFAULT_PORT
    except OSError:
        port = await find_available_port(DEFAULT_PORT + 1)
        server = await asyncio.start_server(lambda r, w: asyncio.create_task(handle_receiver(r)), HOST, port)

    print(f"Listening on {HOST}:{port}")

    connect_to_port = DEFAULT_PORT if port != DEFAULT_PORT else DEFAULT_PORT + 1

    while True:
        try:
            reader, writer = await asyncio.open_connection(HOST, connect_to_port)
            print(f"Connected to {HOST}:{connect_to_port}")
            break
        except Exception:
            await asyncio.sleep(1)

    await asyncio.gather(
        handle_transmitter(writer),
        server.serve_forever()
    )

asyncio.run(start_transceiver())

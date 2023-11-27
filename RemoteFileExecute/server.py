import socket
import argparse
import os

BUFFER_SIZE = 2048

def send_file(client_socket, file_path):
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
            client_socket.sendall(file_data)
    except FileNotFoundError:
        print("File not found")
    except Exception as e:
        print(f"Error: {str(e)}")

def start_server(listen_port, payload_exe):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', listen_port))
    server_socket.listen(5)
    print(f"Server listening on port {listen_port}...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")

        try:
            while True:
                request = client_socket.recv(1024).decode('utf-8')
                if not request:
                    break  # ≈сли клиент закрыл соединение, выходим из цикла

                print(f"Received message: {request}")

                if request == "GetFileSize":
                    file_size = os.path.getsize(payload_exe)
                    client_socket.send(str(file_size).encode('utf-8'))
                elif request == "start":
                    send_file(client_socket, payload_exe)
                else:
                    response = "Invalid request"
                    client_socket.send(response.encode('utf-8'))
        except ConnectionResetError:
            print(f"Connection with {addr} reset by peer")
        finally:
            client_socket.close()
            print(f"Connection with {addr} closed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TCP Server with custom arguments")
    parser.add_argument("--lport", type=int, default=8888, help="Listening port")
    parser.add_argument("--pe", type=str, required=True, help="Payload executable")

    args = parser.parse_args()

    start_server(args.lport, args.pe)

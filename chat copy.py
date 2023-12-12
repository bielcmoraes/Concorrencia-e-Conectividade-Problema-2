import socket
import threading
import os
import platform
import json
import time
from queue import Queue
from lamport_clock import LamportClock

peer_addresses = [("192.168.43.198", 7777), ("192.168.43.198", 2222), ("192.168.43.198", 1111)]
received_packets = Queue()
lamport_clock = LamportClock()
my_info = (None, None)
all_messages = []


def encrypt_message(frase, port):
    mensagem = ""
    for i in frase:
        mensagem += chr (ord(i) + port)
    return mensagem

def decrypt_message(mensagem, port):
    frase = ""
    for i in mensagem:
        frase += chr (ord(i) - port)
    return frase

def receive_messages(udp_socket):

    
    while True:
        try:
            data, addr = udp_socket.recvfrom(1024)
            received_packets.put((addr, data))
        except OSError as e:
            print("Erro no socket: ", e)

def send_messages(udp_socket):
    
    while True:
        message_text = input("Digite as mensagens (ou 'exit' para sair): ")

        if message_text.lower() == 'exit':
            break

        # Gere um novo ID de mensagem
        message_id = lamport_clock.get_time()

        # Crie um dicionário para a mensagem em formato JSON
        message_data = {
            "message_type": "Message",
            "message_id": message_id,
            "text": message_text
        }

        # Serializar a mensagem em JSON
        message_json = json.dumps(message_data)

        # Enviar a mensagem para todos os pares
        for peer_addr in peer_addresses:
            if peer_addr != my_info:
                encrypted_message = encrypt_message(message_json, 5)
                if encrypted_message:
                    udp_socket.sendto(encrypted_message.encode("utf-8"), peer_addr)
            
        message_save = (my_info, message_data)
        if message_save not in all_messages:
            all_messages.append(message_save)
            lamport_clock.increment()

def order_packages(udp_socket):
    global received_packets
    
    while True:
        package_received = received_packets.get()
        addr = package_received[0]
        data = package_received[1]

        try:
            data_decrypt = decrypt_message(data.decode("utf-8"), 5)

            if data_decrypt:
                # Desserializar a mensagem JSON
                message_data = json.loads(data_decrypt)
                print("message_data", message_data)

                if "message_type" in message_data:
                    message_type = message_data["message_type"]
                    if message_type == "Message":
                        if "message_id" in message_data and "text" in message_data:
                            message_id = message_data["message_id"]

                            # Adicione a mensagem à lista de mensagens
                            if ((addr, message_data)) not in all_messages:
                                all_messages.append((addr, message_data))  # Tupla com endereço/porta e mensagem
                                lamport_clock.update(message_id)
   
        except Exception as e:
            print("Erro ao ordenar pacotes: ", e)

def order_messages(messages):
    # Utilize a função sorted do Python, fornecendo a função de ordenação com base no carimbo de tempo e, em caso de empate, no maior valor em messages[0]
    ordered_messages = sorted(messages, key=lambda x: (x[1]["message_id"], x[0]))
    return ordered_messages

def read_messages():
    
    all_messages_sorted = order_messages(all_messages)
    print("\nTodas as mensagens: ")
    for message_data in all_messages_sorted:
        address = message_data[0]
        text = message_data[1]['text']
        message_id = message_data[1]['message_id']
        if address == my_info:
            print(f"My message({message_id}): {text}")
        else:
            print(f"{address}({message_id}): {text}") 
    print()

def main():
    global my_info

    my_ip = input("Digite seu endereço IP: ")
    my_port = int(input("Digite sua porta: "))
    my_info = (my_ip, my_port)

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((my_ip, my_port))

    try:
        if udp_socket and udp_socket.fileno() != -1:

            # Iniciar a thread para receber mensagens 
            receive_thread = threading.Thread(target=receive_messages, args=(udp_socket, ))
            receive_thread.daemon = True
            receive_thread.start()

            order_packages_thread = threading.Thread(target=order_packages, args=(udp_socket, ))
            order_packages_thread.daemon = True
            order_packages_thread.start()

            while True:
                print("[2] Para enviar mensagens")
                print("[3] Para visualizar mensagens")
                print("[4] Para sair")

                menu_main = int(input())

                if menu_main == 2:
                    # Inicie a função send_messages na thread principal
                    send_messages(udp_socket)
                    # clear_terminal()

                elif menu_main == 3:
                    read_messages()
    except socket.timeout:
        pass


if __name__ == "__main__":
    main()
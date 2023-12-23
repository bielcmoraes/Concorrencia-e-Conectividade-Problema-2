import socket
import threading
import os
import platform
import json
import time
from queue import Queue
from lamport_clock import LamportClock

peer_addresses = [("172.16.103.1", 5555), ("172.16.103.2", 5555), ("172.16.103.3", 5555), ("172.16.103.4", 5555), ("172.16.103.5", 5555), ("172.16.103.6", 5555), ("172.16.103.7", 5555), ("172.16.103.8", 5555), ("172.16.103.9", 5555), ("172.16.103.10", 5555), ("172.16.103.11", 5555), ("172.16.103.12", 5555), ("172.16.103.13", 5555), ("172.16.103.14", 5555)]
received_packets = Queue()
lamport_clock = LamportClock()
my_info = (None, None)
all_messages = []

OPERATION_NUMBER = 5

# Função para sincronizar mensagens
def start_sync():

    # Gere um novo ID de mensagem
    message_id = lamport_clock.get_time()

    # Crie um dicionário para a mensagem em formato JSON
    message_data = {
        "message_type": "Sync",
        "message_id": [my_info[0], message_id],
        "text": "Start sync."
    }

    # Serializar a mensagem em JSON
    message_json = json.dumps(message_data)

    encrypted_message = encrypt_message(message_json, OPERATION_NUMBER)
    # Enviar a mensagem para todos os pares
    send_pacote(encrypted_message)

# Função para solicitar sincronização a cada "X" tempo
def time_sync():
    while True:
        start_sync()
        time.sleep(5)

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

def receive_messages():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(my_info)

    while True:
        data, addr = udp_socket.recvfrom(2048)
        received_packets.put((addr, data))

def send_pacote(objMsg):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for peer_addr in peer_addresses:
            if peer_addr != my_info:
                    client_socket.sendto(objMsg.encode(), peer_addr)
    except Exception as e:
        print("Erro ao enviar pacote: ", e)
    finally:
        client_socket.close()

def send_messages():
    while True:
        message_text = input("Digite as mensagens (ou 'exit' para sair): ")

        if message_text.lower() == 'exit':
            break

        # Gere um novo ID de mensagem
        message_id = lamport_clock.get_time()

        # Crie um dicionário para a mensagem em formato JSON
        message_data = {
            "message_type": "Message",
            "message_id": [my_info[0], message_id],
            "text": message_text
        }

        # Serializar a mensagem em JSON
        message_json = json.dumps(message_data)

        # Enviar a mensagem para todos os pares
        
        encrypted_message = encrypt_message(message_json, OPERATION_NUMBER)
        if encrypted_message:
            send_pacote(encrypted_message)

        message_save = (my_info[0], message_data)
        if message_save not in all_messages:
            all_messages.append(message_save)
            lamport_clock.increment()

def order_packages():
    
    while True:
        package_received = received_packets.get()
        addr = package_received[0]
        data = package_received[1]

        try:
            data_decrypt = decrypt_message(data.decode("utf-8"), OPERATION_NUMBER)

            if data_decrypt:
                # Desserializar a mensagem JSON
                message_data = json.loads(data_decrypt)

                if "message_type" in message_data:
                    message_type = message_data["message_type"]
                    if message_type == "Message":
                        # {'message_type': 'Message', 'message_id': ['192.168.43.107', 9], 'text': 'fala tu'}
                        if "message_id" in message_data and "text" in message_data:
                            message_id = message_data["message_id"]

                            # Adicione a mensagem à lista de mensagens
                            if ((message_id[0], message_data)) not in all_messages:
                                print(message_data)
                                all_messages.append((message_id[0], message_data))  # Tupla com endereço/porta e mensagem
                                lamport_clock.update(message_id[1])
                                
                    elif message_type == "Sync":
                            
                            if "message_id" in message_data and "text" in message_data:
                                text_sync = message_data["text"]
                                if "Start sync" in text_sync:  # Envia a lista de pares atualizada e a lista de mensagens

                                # Id da lista de mensagens que será enviada                                
                                    # Envie a lista de mensagens atual
                                    for message in all_messages:
                                        message_json = json.dumps(message[1])
                                        message_encrypted = encrypt_message(message_json, OPERATION_NUMBER)
                                        send_pacote(message_encrypted)
   
        except Exception as e:
            print("Erro ao ordenar pacotes: ", e)

def order_messages(messages):
    # Utilize a função sorted do Python, fornecendo a função de ordenação com base no carimbo de tempo e, em caso de empate, no maior valor em messages[0]
    ordered_messages = sorted(messages, key=lambda x: (x[1]["message_id"][1], x[0]))
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

# Função para limpar o terminal independente do S.O
def clear_terminal():
    current_os = platform.system()
    if current_os == "Windows":
        os.system("cls")
    else:
        os.system("clear")

def main():
    global my_info

    my_ip = input("Digite seu endereço IP: ")
    my_port = int(input("Digite sua porta: "))
    my_info = (my_ip, my_port)

    try:
            # Iniciar a thread para receber mensagens 
            receive_thread = threading.Thread(target=receive_messages)
            receive_thread.daemon = True
            receive_thread.start()

            order_packages_thread = threading.Thread(target=order_packages)
            order_packages_thread.daemon = True
            order_packages_thread.start()

            # Iniciar a thread para solicitar constantemente a sincronização do sistema a cada "X" tempo
            time_sync_thread = threading.Thread(target=time_sync)
            time_sync_thread.daemon = True
            time_sync_thread.start()

            # clear_terminal()

            while True:
                print("[1] Para enviar mensagens")
                print("[2] Para visualizar mensagens")
                print("[3] Para sair")

                menu_main = int(input())

                if menu_main == 1:
                    # Inicie a função send_messages na thread principal
                    send_messages()
                    # clear_terminal()

                elif menu_main == 2:
                    read_messages()

                elif menu_main == 3:
                    # Feche o socket ao sair                    
                    print("---Encerrando conexões---")
                    exit()
    except socket.timeout:
        pass


if __name__ == "__main__":
    main()
import socket
import threading
import os
import platform
import json
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

from queue import Queue
from lamport_clock import LamportClock

# Relogio lógico
lamport_clock = LamportClock()

# Lista de pares participantes do grupo
peer_addresses = [("192.168.43.198", 6666), ("172.16.103.2", 7777)]

# Lista de pares online
peers_on = []

# Dicionário para armazenar as chaves públicas dos pares
public_keys = {}

# Todos os pacotes recebidos
received_packets = Queue()
                                                                                                  
# Lista global para armazenar todas as mensagens
all_messages = []

# Dicionário para rastrear pacotes não confirmados e seus horários de envio
unconfirmed_packets = {}

# Dicionário para armazenar as mensagens de confirmação
confirmation_messages = {}

# Dicionário para armazenar as mensagens que foram recebidas em partes e não estão completas ainda
parts_messages = Queue()

# Lock para proteger as sincronização
sync_lock = threading.Lock()

# Lock para proteger os pacotes não confirmados

# Função para sincronizar mensagens
def start_sync():
    global peer_addresses
    global udp_socket
    global public_keys

    # Gere um novo ID de mensagem
    message_id = lamport_clock.get_time()

    # Crie um dicionário para a mensagem em formato JSON
    message_data = {
        "message_type": "Sync",
        "message_id": message_id,
        "text": "Start sync."
    }

    # Serializar a mensagem em JSON
    message_json = json.dumps(message_data)

    # Enviar a mensagem para todos os pares
    for peer_addr in peer_addresses:
        public_key_bytes = public_keys.get(peer_addr)
        if public_key_bytes != None:
            encrypted_message = encrypt_message(message_json,5)
            udp_socket.sendto(encrypted_message.encode("utf-8"), peer_addr)

# Função para enviar todas as mensagens ou lista de pares e prosseguir com a sincronização
def send_sync(udp_socket, content, size, part, sync_id):
    global peer_addresses
    global public_keys
    global unconfirmed_packets

    # Desserializar a parte da mensagem
    # Crie um dicionário para a mensagem em formato JSON

    # Serializar a mensagem em JSON
    message_json_enviar = json.dumps(part)

    try:
        # Enviar a mensagem para todos os pares
            for peer_addr in peer_addresses:
                # Adicione o pacote não confirmado ao dicionário
                encrypted_message = encrypt_message(message_json_enviar, 5)
                udp_socket.sendto(encrypted_message.encode("utf-8"), peer_addr)
                print("Part: ", message_json_enviar)
    except:
        pass

# Função para solicitar sincronização a cada "X" tempo
def time_sync():
    while True:
        time.sleep(20)
        start_sync()

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

# Função para enviar mensagens de texto
def send_messages(udp_socket, my_ip, my_port, my_public_key_bytes):
    global peer_addresses
    global public_keys

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
            
            encrypted_message = encrypt_message(message_json, 5)
            if encrypted_message:
                udp_socket.sendto(encrypted_message.encode("utf-8"), peer_addr)
                print("ECRY", encrypted_message)
            
        message_save = ((my_ip, my_port), message_data)
        if message_save not in all_messages:
            all_messages.append(message_save)
            lamport_clock.increment()

def order_packages(udp_socket, private_key_str, my_public_key):
    global received_packets
    
    while True:
        
        package_received = received_packets.get()
        print("\npackage_received: ", package_received, '\n')
            
        addr = package_received[0]
        data = package_received[1]

        try:
            print(data)
            data_decrypt = decrypt_message(data.decode("utf-8"), 5)
            print("DEPOIS: ", data_decrypt)

            if data_decrypt:
                # Desserializar a mensagem JSON
                message_data = json.loads(data_decrypt)
                
                print("ZZZZ", message_data)

                if "message_type" in message_data:
                    message_type = message_data["message_type"]
                    if message_type == "Message":
                        if "message_id" in message_data and "text" in message_data:
                            message_id = message_data["message_id"]

                            # Adicione a mensagem à lista de mensagens
                            if ((addr, message_data)) not in all_messages:
                                all_messages.append((addr, message_data))  # Tupla com endereço/porta e mensagem
                                lamport_clock.update(message_id)

                    elif message_type == "Confirmation":
                        if "message_id" in message_data:
                            message_id = message_data["message_id"]

                            # Adiciona ao dicionário de mensagens de confirmação
                            confirmation_messages_exists = confirmation_messages.get(message_id)
                            if confirmation_messages_exists is not None:
                                confirmation_messages[message_id].append(message_data)
                            else:
                                confirmation_messages[message_id] = [message_data]

                    elif message_type == "Sync":
                        print(message_data)
                        if "message_id" in message_data and "text" in message_data:
                            text_sync = message_data["text"]
                            if "Start sync" in text_sync:  # Envia a lista de pares atualizada e a lista de mensagens

                                # Id da lista de mensagens que será enviada                                
                                with sync_lock:
                                    # Envie a lista de mensagens atual
                                    for message in all_messages:
                                        send_sync(udp_socket, None, None, message, None)
                                    print("enviei att")
                            elif "message_id" in message_data and "content" in message_data and "size" in message_data:
                                # Parte da mensagem sendo recebida durante a sincronização
                                # Id da mensagem particionada
                                message_id = message_data["sync_id"]

        
        except Exception as e:
            # print("A mensagem que chegou é descriptografada", e)
            pass

        #received_packets.remove(package_received) #Remove o pacote

def receive_messages(udp_socket):
    global received_packets
    global public_keys
    global peers_on

    while True:
        try:
            data, addr = udp_socket.recvfrom(2048)
            
            received_packets.put((addr, data))

        except socket.timeout as e:
            pass

        except OSError as e:
            if e.errno == 10054 and udp_socket.fileno() == -1:
                udp_socket = conect_socket((my_ip, my_port))

# Função para ordenar as mensagens com base no carimbo de tempo (time_stamp)
def order_messages(messages):
    # Utilize a função sorted do Python, fornecendo a função de ordenação com base no carimbo de tempo e, em caso de empate, no maior valor em messages[0]
    ordered_messages = sorted(messages, key=lambda x: (x[1]["message_id"], x[0]))
    return ordered_messages

# Função para ler todas as mensagens
def read_messages(my_addr):

    global all_messages
    global all_messages_sorted
    global parts_messages
    global confirmation_messages
    
    all_messages_sorted = order_messages(all_messages)
    print("\nTodas as mensagens: ")
    for message_data in all_messages_sorted:
        address = message_data[0]
        text = message_data[1]['text']
        message_id = message_data[1]['message_id']
        if address == my_addr:
            print(f"My message({message_id}): {text}")
        else:
            print(f"{address}({message_id}): {text}") 
    print()
    return

# Função para limpar o terminal independente do S.O
def clear_terminal():
    current_os = platform.system()
    if current_os == "Windows":
        os.system("cls")
    else:
        os.system("clear")

# Função para criar um socket
def creat_socket(addr):

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Configurar a opção SO_REUSEADDR para que endereço e porta possam ser reaproveitados
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Inicio um novo socket
    udp_socket.bind(addr)
    udp_socket.settimeout(5)  # Defina um timeout de 2 segundos
    return udp_socket

# função de conexão
def conect_socket(addr):
    global udp_socket
    while True:
        try:
            udp_socket = creat_socket(addr)
            print("Conexão bem-sucedida!")
            return udp_socket
        except socket.error as e:
            print(f"Falha na reconexão: {e}")
            time.sleep(5)  # Aguarde antes de tentar novamente

# Função principal
def main(my_ip, my_port, udp_socket, private_key_str, public_key_bytes):
    global peer_addresses

    try:
        # clear_terminal()
            
        if udp_socket and udp_socket.fileno() != -1:   
            
            # Iniciar a thread para receber mensagens 
            receive_thread = threading.Thread(target=receive_messages, args=(udp_socket, ))
            receive_thread.daemon = True
            receive_thread.start()

            order_packages_thread = threading.Thread(target=order_packages, args=(udp_socket, private_key_str, public_key_bytes))
            order_packages_thread.daemon = True
            order_packages_thread.start()

            # Iniciar a thread para solicitar constantemente a sincronização do sistema a cada "X" tempo
            time_sync_thread = threading.Thread(target=time_sync)
            time_sync_thread.daemon = True
            time_sync_thread.start()

            while True:
                print("[1] Para adicionar participantes a um grupo")
                print("[2] Para enviar mensagens")
                print("[3] Para visualizar mensagens")
                print("[4] Para sair")

                menu_main = int(input())

                if menu_main == 1:
                    num_peers = int(input("Quantos participantes deseja adicionar no grupo?"))

                    for _ in range(num_peers):
                        peer_ip = input("Digite o endereço IP do par: ")
                        peer_port = int(input("Digite a porta do par: "))
                        peer_address = (peer_ip, peer_port)
                        peer_addresses.append(peer_address)

                        # Envie para todos os pares que alguém foi adicionado ao grupo
                        message_text = f"{my_ip}:{my_port} added {peer_ip}:{peer_port} to the group"
                        udp_socket.sendto(message_text.encode('utf-8'), peer_address)
                    # clear_terminal()

                elif menu_main == 2:
                    # Inicie a função send_messages na thread principal
                    send_messages(udp_socket, my_ip, my_port, public_key_bytes)
                    # clear_terminal()

                elif menu_main == 3:
                    read_messages((my_ip, my_port))

                elif menu_main == 4:
                    # Feche o socket ao sair
                    for peer in peer_addresses:
                        udp_socket.sendto("END".encode('utf-8'), peer)
                    
                    print("---Encerrando conexões---")
                    time.sleep(5)
                    udp_socket.close()
                    exit()
    except socket.timeout:
        pass

if __name__ == "__main__":

    # Gerar um par de chaves RSA
    private_key = None

    # Exportar as chaves pública e privada
    private_key_str = None
    public_key = None
    public_key_bytes = None
    
    my_ip = input("Digite seu endereço IP: ")
    
    my_port = int(input("Digite sua porta: "))

    udp_socket = conect_socket((my_ip, my_port))

    # Inicie a função principal na thread principal
    main(my_ip, my_port, udp_socket, private_key_str, public_key_bytes)
import queue
import socket
import sys
import threading
import uuid
import os
import platform
import json
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

# Lista de pares participantes do grupo
peer_addresses = [("192.168.0.121", 6666)]

# Lista de pares online
peers_on = []

# Dicionário para armazenar as chaves públicas dos pares
public_keys = {}

# Lista global para armazenar todas as mensagens
all_messages = []

# Dicionário para rastrear pacotes não confirmados e seus horários de envio
unconfirmed_packets = {}

# Dicionário para armazenar as mensagens de confirmação
confirmation_messages = {}

# Dicionário para armazenar as mensagens que foram recebidas em partes e não estão completas ainda
parts_messages = {}

# Lock para proteger a leitura de mensagens
messages_lock = threading.Lock()

# Lock para proteger a atualização do socket
udp_socket_lock = threading.Lock()

# Lock para proteger as chaves públicas
public_keys_lock = threading.Lock()

# Pares online lock
peers_on_lock = threading.Lock()

# Lock para proteger as sincronização
sync_lock = threading.Lock()

# Lock para proteger os pacotes não confirmados
unconfirmed_packets_lock = threading.Lock()

# Função para sincronizar mensagens
def start_sync():
    global peer_addresses
    global udp_socket
    global public_keys
    global public_keys_lock

    # Gere um novo ID de mensagem
    message_id = str(uuid.uuid4())

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
            with public_keys_lock:
                public_key_bytes = public_keys.get(peer_addr)
                if public_key_bytes:
                    encrypted_message = encrypt_message(message_json, public_key_bytes)
                    udp_socket.sendto(encrypted_message, peer_addr)

# Função para enviar todas as mensagens ou lista de pares e prosseguir com a sincronização
def send_sync(udp_socket, content, size, part):
    global peer_addresses
    global public_keys
    global unconfirmed_packets
    global public_keys_lock

    # Desserializar a parte da mensagem
    print("1:", part)
    # Crie um dicionário para a mensagem em formato JSON
    message_json = {
        "message_type": "Sync",
        "message_id": part["message_id"],
        "content": content,
        "size": size,
        "last_message_id": part["last_message_id"],
        "text": part["text"]
    }

    # Serializar a mensagem em JSON
    message_json_enviar = json.dumps(message_json)

    try:
        # Enviar a mensagem para todos os pares
        with public_keys_lock:
            for peer_addr in peer_addresses:
                # Adicione o pacote não confirmado ao dicionário
                unconfirmed_packets[id] = {"packet": message_json_enviar.encode('utf-8'), "address": peer_addr, "send_time": time.time()}
                public_key_bytes = public_keys.get(peer_addr)
                while public_key_bytes is None:
                    public_key_bytes = public_keys.get(peer_addr)
                encrypted_message = encrypt_message(message_json_enviar, public_key_bytes)
                udp_socket.sendto(encrypted_message, peer_addr)
    except:
        pass

# Função para reenviar pacotes não confirmados
def resend_unconfirmed_packets(udp_socket):

    global unconfirmed_packets

    while len(unconfirmed_packets) > 0:
        time.sleep(1)  # Verificar a cada segundos
        try:
            for message_id, packet_info in list(unconfirmed_packets.items()):
                send_time = packet_info["send_time"]
                # Verifique se o tempo desde o envio excedeu um limite (por exemplo, 10 segundos)
                if time.time() - send_time > 5:
                    # Reenvie o pacote correspondente
                    packet_data = unconfirmed_packets.pop(message_id)
                    udp_socket.sendto(packet_data["packet"], packet_data["address"])
                    # Atualize o horário de envio
                    unconfirmed_packets[message_id] = {"packet": packet_data["packet"], "address": packet_data["address"], "send_time": time.time()}
                    print(unconfirmed_packets)
        except:
            pass

# função para juntar as partes das mensagens no local adequado
def system_sync():
    global parts_messages
    global peer_addresses
    global all_messages
    global all_packages

    while True:

        # Crie uma cópia do dicionário para evitar o erro durante a iteração
        parts_messages_copy = dict(parts_messages)
        for package_id in parts_messages_copy:
            package_list = parts_messages_copy.get(package_id)
            if len(package_list) == package_list[0]["size"]: # Verifica se todas as partes chegaram
                if package_list[0]["content"] == "peer_addresses":
                    for package in package_list:
                        if tuple(package["part"]) not in peer_addresses and (my_ip, my_port) != tuple(package["part"]):
                            peer_addresses.append(tuple(package["part"]))
                        
                elif package_list[0]["content"] == "messages_list": 
                    for package in package_list:
                        new_package = {
                            "message_type": "Message",
                            "message_id": package["message_id"],
                            "last_message_id": package["last_message_id"],
                            "text": package["text"]
                        }
                        with messages_lock:
                            if new_package["text"] not in all_messages:
                                all_messages.append(new_package)
                
                parts_messages.pop(package_id) # Retira os pacotes completos que já foram sincronizados da lista

# Função para criptografar uma mensagem com a chave pública serializada
def encrypt_message(message, public_key_bytes):
    try:

        public_key = serialization.load_pem_public_key(public_key_bytes)
        encrypted_message = public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("ENCRYPT:", encrypted_message)
        return encrypted_message
    except Exception as e:
        print(f"Erro ao criptografar a mensagem: {e}")
        pass

# Função para descriptografar uma mensagem com a chave privada serializada
def decrypt_message(encrypted_message, private_key_str):
    try:
        private_key = serialization.load_pem_private_key(private_key_str, password=None)
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode('utf-8')
    except Exception as e:
        raise Exception("Erro na descriptografia")

# Trata a confirmação de mensagens
def handle_confirmations():
    global unconfirmed_packets
    global confirmation_messages

    while True:
        for message_id in list(unconfirmed_packets.keys()):
            if message_id in confirmation_messages:
                del unconfirmed_packets[message_id]
                del confirmation_messages[message_id]
        time.sleep(1)

# Função para enviar mensagens de texto
def send_messages(udp_socket, my_ip, my_port):
    global peer_addresses
    global public_keys
    global public_keys_lock

    while True:

        message_text = input("Digite as mensagens (ou 'exit' para sair): ")

        if message_text.lower() == 'exit':
            break

        # Gere um novo ID de mensagem
        message_id = str(uuid.uuid4())
        with messages_lock:
            # Verifique a posição da mensagem na lista
            if len(all_messages) == 0:
                last_message_id = "first"
            else:
                last_message_id = all_messages[-1][1]["message_id"]

        # Crie um dicionário para a mensagem em formato JSON
        message_data = {
            "message_type": "Message",
            "message_id": message_id,
            "last_message_id": last_message_id,
            "text": message_text
        }

        # Serializar a mensagem em JSON
        message_json = json.dumps(message_data)

        
        # Enviar a mensagem para todos os pares
        for peer_addr in peer_addresses:

            public_key_bytes = None
            while public_key_bytes is None:
                public_key_bytes = public_keys.get(peer_addr)
                # Adicione um pequeno atraso antes de tentar novamente para evitar uso excessivo da CPU
                time.sleep(1)
            if public_key_bytes:
                encrypted_message = encrypt_message(message_json, public_key_bytes)
                if encrypted_message:
                    udp_socket.sendto(encrypted_message, peer_addr)
            
            # Crie um dicionário para a confirmação em formato JSON
            confirmation_data = {
                "message_type": "Confirmation",
                "message_id": message_id
            }

            # Serializar a confirmação em JSON
            confirmation_json = json.dumps(confirmation_data)

            encrypted_confirmation = encrypt_message(confirmation_json, public_key_bytes)

            if encrypted_confirmation:
            # Envie a confirmação
                udp_socket.sendto(encrypted_confirmation, peer_addr)
                unconfirmed_packets[message_id] = {"packet": message_json.encode('utf-8'), "address": peer_addr, "send_time": time.time()}

        message_save = ((my_ip, my_port), message_data)
        with messages_lock:
            if message_save not in all_messages:
                all_messages.append(message_save)

def receive_messages(udp_socket, private_key_str, my_public_key):
    global public_keys
    global public_keys_lock
    global peers_on

    while True:
        try:
            data, addr = udp_socket.recvfrom(2048)
            try:
                data_decode = data.decode('utf-8')
                
                if "-----BEGIN PUBLIC KEY-----" in data_decode and "-----END PUBLIC KEY-----" in data_decode:
                    with public_keys_lock:
                        public_keys.clear()
                        public_keys[addr] = data
                        
                    if addr in peers_on:
                        udp_socket.sendto(my_public_key, addr)
                        
                    else:
                        udp_socket.sendto(my_public_key, addr)
                        peers_on.append(addr)
                        start_sync()
                                  

                if data_decode == "END":
                    peers_on.remove(addr)
                    print(addr, "ficou offline...")

            except Exception as e:
                pass

            try:
                data_decrypt = decrypt_message(data, private_key_str)

                if data_decrypt:
                    # Desserializar a mensagem JSON
                    message_data = json.loads(data_decrypt)
                    
                    # Garente a captura da chave e eu sei que ela existe porque o pacote chegou aqui
                    with messages_lock:
                        public_key_str = None
                        while public_key_str is None:
                            public_key_str = public_keys.get(addr)
                            # Adicione um pequeno atraso antes de tentar novamente para evitar uso excessivo da CPU
                            time.sleep(1)

                    if "message_type" in message_data:
                        message_type = message_data["message_type"]
                        if message_type == "Message":
                            if "message_id" in message_data and "text" in message_data:
                                message_id = message_data["message_id"]

                                # Enviar confirmação de entrega da mensagem com o mesmo ID
                                confirmation_message = {
                                    "message_type": "Confirmation",
                                    "message_id": message_id
                                }

                                # Serializar e criptografar a confirmação antes de enviar
                                confirmation_json = json.dumps(confirmation_message)
                                encrypted_confirmation = encrypt_message(confirmation_json, public_key_str)

                                udp_socket.sendto(encrypted_confirmation, addr)

                                with messages_lock:
                                    # Adicione a mensagem à lista de mensagens
                                    if ((addr, message_data)) not in all_messages:
                                        all_messages.append((addr, message_data))  # Tupla com endereço/porta e mensagem

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
                            if "message_id" in message_data and "text" in message_data:
                                text_sync = message_data["text"]
                                if "Start sync" in text_sync:  # Envia a lista de pares atualizada e a lista de mensagens
                                    
                                    with sync_lock:
                                        # Envie a chave minha pública para todos os pares que desejam sincronizar
                                        for peer in peer_addresses:
                                            udp_socket.sendto(my_public_key, peer)

                                    # # Id da lista de pares que será enviada
                                    # message_list_peers_id = str(uuid.uuid4())
                                    # # Tamanho da lista de pares que será enviada/quantidade de partes que será enviada
                                    # peers_size = len(peer_addresses)

                                    # with sync_lock:
                                    #     # Envie a lista de pares atual
                                    #     for peer in peer_addresses:
                                    #         send_sync_thread = threading.Thread(target=send_sync, args=(udp_socket, message_list_peers_id, "peer_addresses", peers_size, peer))
                                    #         send_sync_thread.daemon = True
                                    #         send_sync_thread.start()

                                    # Id da lista de mensagens que será enviada
                                    message_list_message_id = str(uuid.uuid4())
                                    
                                    with messages_lock:
                                        with sync_lock:
                                            # Tamanho da lista de mensagens que será enviada/quantidade de partes que será enviada
                                            messages_size = len(all_messages)
                                            # Envie a lista de mensagens atual
                                            for message in all_messages:
                                                send_sync(udp_socket, "messages_list", messages_size, message[1])

                            elif "message_id" in message_data and "content" in message_data and "size" in message_data and "part" in message_data:
                                
                                # Parte da mensagem sendo recebida durante a sincronização
                                # Id da mensagem particionada
                                message_id = message_data["message_id"]

                                # Verifica se existe uma chave para a parte da mensagem e cria caso não exista
                                message_part_exists = parts_messages.get(message_id)
                                if message_part_exists is not None:
                                    parts_messages[message_id].append(message_data)
                                else:
                                    parts_messages[message_id] = [message_data]

                                # Enviar confirmação de entrega da mensagem com o mesmo ID
                                confirmation_message = {
                                    "message_type": "Confirmation",
                                    "message_id": message_id
                                }

                                with messages_lock:
                                    public_key_str = None
                                    while public_key_str is None:
                                        public_key_str = public_keys.get(addr)
                                        # Adicione um pequeno atraso antes de tentar novamente para evitar uso excessivo da CPU
                                        time.sleep(1)

                                # Serializar e criptografar a confirmação antes de enviar
                                confirmation_json = json.dumps(confirmation_message)
                                encrypted_confirmation = encrypt_message(confirmation_json, public_key_str)

                                udp_socket.sendto(encrypted_confirmation, addr)

            except Exception as e:
                # print("A mensagem que chegou é descriptografada", e)
                pass

        except socket.timeout as e:
            # print("socket.timeout:", e)
            pass

        except OSError as e:
            # print("socket.OSError:", e)
            if e.errno == 10054 and udp_socket.fileno() == -1:
                udp_socket = conect_socket((my_ip, my_port))

def clear_connection_data():
    global public_keys
    global peers_on
    global unconfirmed_packets
    global confirmation_messages
    global parts_messages

    with public_keys_lock:
        public_keys = {}
    with peers_on_lock:
        peers_on = []
    with unconfirmed_packets_lock:
        unconfirmed_packets = {}
    with sync_lock:
        confirmation_messages = {}
        parts_messages = {}

def order_messages(unordered_messages):
    # Função auxiliar para calcular a chave de ordenação
    def sort_key(message_tuple):
        sender_address, message = message_tuple
        last_message_id = message.get("last_message_id")
        message_id = message.get("message_id")

        # Converter as strings em UUIDs válidos
        try:
            last_message_id = uuid.UUID(last_message_id)
        except ValueError:
            last_message_id = uuid.UUID(int=0)  # Usar valor padrão se não for um UUID válido

        try:
            message_id = uuid.UUID(message_id)
        except ValueError:
            message_id = uuid.UUID(int=0)  # Usar valor padrão se não for um UUID válido

        # Atribuir um valor especial para mensagens com "last_message_id" igual a "first"
        if last_message_id == "first":
            return (uuid.UUID(int=0), message_id)
        elif last_message_id is None:
            return (uuid.UUID(int=1), message_id)  # Usar outro UUID como valor especial
        return (last_message_id, message_id)

    # Filtrar mensagens com last_message_id igual a "first" e ordenar o restante
    first_messages = [message_tuple for message_tuple in unordered_messages if message_tuple[1].get("last_message_id") == "first"]
    other_messages = [message_tuple for message_tuple in unordered_messages if message_tuple[1].get("last_message_id") != "first"]
    ordered_messages = first_messages + sorted(other_messages, key=sort_key)

    return ordered_messages

# Função para ler todas as mensagens
def read_messages():

    global all_messages
    global all_messages_sorted
    global parts_messages
    global confirmation_messages
    with messages_lock:
        all_messages_sorted = order_messages(all_messages)
        print("\nTodas as mensagens: ")
        for message_data in all_messages_sorted:
            print(message_data)
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
    udp_socket.settimeout(2)  # Defina um timeout de 2 segundos
    return udp_socket

# função de conexão
def conect_socket(addr):
    global udp_socket
    while True:
        try:
            clear_connection_data()
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

            # Aguarde a sincronização inicial ser concluída (você pode ajustar o tempo conforme necessário)
            time.sleep(5)

            # Iniciar a thread para receber mensagens
            receive_thread = threading.Thread(target=receive_messages, args=(udp_socket, private_key_str, public_key_bytes))
            receive_thread.daemon = True
            receive_thread.start()

            # Iniciar a thread para sincronizar constantemente o sistema a cada "X" tempo
            sync_thread = threading.Thread(target=system_sync)
            sync_thread.daemon = True
            sync_thread.start()

            # Iniciar a thread para reenviar pacotes não confirmados
            resend_unconfirmed_packets_thread = threading.Thread(target=resend_unconfirmed_packets, args=(udp_socket,))
            resend_unconfirmed_packets_thread.daemon = True
            resend_unconfirmed_packets_thread.start()

            # Iniciar a thread para lidar com as confirmações
            handle_confirmations_thread = threading.Thread(target=handle_confirmations)
            handle_confirmations_thread.daemon = True
            handle_confirmations_thread.start()


            start_sync()

            # Envie a chave pública para todos os pares da lista
            for peer in peer_addresses:
                udp_socket.sendto(public_key_bytes, peer)

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
                    with udp_socket_lock:
                        send_messages(udp_socket, my_ip, my_port)
                    # clear_terminal()

                elif menu_main == 3:
                    read_messages()

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
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Exportar as chaves pública e privada
    private_key_str = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    my_ip = input("Digite seu endereço IP: ")
    
    my_port = int(input("Digite sua porta: "))

    udp_socket = conect_socket((my_ip, my_port))

    # Inicie a função principal na thread principal
    main(my_ip, my_port, udp_socket, private_key_str, public_key_bytes)
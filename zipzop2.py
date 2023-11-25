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
peer_addresses = [("192.168.0.180", 4444)]

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

# Função para sincronizar mensagens
def start_sync(udp_socket):
    global peer_addresses

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
            public_key_bytes = public_keys.get(peer_addr)
            if public_key_bytes:
                encrypted_message = encrypt_message(message_json, public_key_bytes)
                udp_socket.sendto(encrypted_message, peer_addr)
    
    print("SYNC ENVIADO")

# Função para enviar todas as mensagens ou lista de pares e prosseguir com a sincronização
def send_sync(udp_socket, id, content, size, part):
    global peer_addresses
    global public_keys
    global unconfirmed_packets

    # Crie um dicionário para a mensagem em formato JSON
    message_data = {
        "message_type": "Sync",
        "message_id": id,
        "content": content,
        "size": size,
        "part": part
    }

    # Serializar a mensagem em JSON
    message_json = json.dumps(message_data)

    # Enviar a mensagem para todos os pares
    for peer_addr in peer_addresses:
            public_key_bytes = public_keys.get(peer_addr)
            if public_key_bytes:
                encrypted_message = encrypt_message(message_json, public_key_bytes)
                udp_socket.sendto(encrypted_message, peer_addr)

                # Adicione o pacote não confirmado ao dicionário
                unconfirmed_packets[id] = {"packet": message_json.encode('utf-8'), "address": peer_addr, "send_time": time.time()}

# Função para reenviar pacotes não confirmados
def resend_unconfirmed_packets(udp_socket):

    global unconfirmed_packets

    while True:
        time.sleep(3)  # Verificar a cada 5 segundos

        for message_id, send_time in list(unconfirmed_packets.items()):
            # Verifique se o tempo desde o envio excedeu um limite (por exemplo, 10 segundos)
            if time.time() - send_time > 5:
                # Reenvie o pacote correspondente
                packet_data = unconfirmed_packets.pop(message_id)
                udp_socket.sendto(packet_data["packet"], packet_data["address"])
                # Atualize o horário de envio
                unconfirmed_packets[message_id] = {"packet": packet_data["packet"], "address": packet_data["address"], "send_time": time.time()}

# função para juntar as partes das mensagens no local adequado
def system_sync():
    
    global parts_messages
    global peer_addresses
    global all_messages

    while True:
        for package_id in parts_messages:
            package_list = parts_messages.get(package_id)
            if len(package_list) == package_list[0]["size"]: # Verifica se todas as partes chegaram
                if package_list[0]["content"] == "peer_addresses":
                    for package in package_list:
                        if package["part"] not in peer_addresses:
                            peer_addresses.append(tuple(package["part"]))
                        
                elif package_list[0]["content"] == "messages_list":
                    for package in package_list:
                        if package["part"] not in all_messages:
                            package["part"]["message_type"] = "Message" #Altera o tipo do pacote para evitar bugs
                            all_messages.append(package["part"])
            
                parts_messages.pop(package_id) # Retira os pacotes completos que já foram sincronizados da lista
        
        # Garante que a sincronização ocorra em um período de tempo pré definido
        time.sleep(20)

# Função para reenviar pacotes não confirmados
def resend_unconfirmed_packets(udp_socket):
    global unconfirmed_packets

    while True:
        time.sleep(5)  # Verificar a cada 5 segundos

        for message_id, packet_data in list(unconfirmed_packets.items()):
            # Verifique se o tempo desde o envio excedeu um limite (por exemplo, 20 segundos)
            if time.time() - packet_data["send_time"] > 20:
                # Reenvie o pacote correspondente
                udp_socket.sendto(packet_data["packet"], packet_data["address"])
                # Atualize o horário de envio
                unconfirmed_packets[message_id]["send_time"] = time.time()

# Função para criptografar uma mensagem com a chave pública serializada
def encrypt_message(message, public_key_bytes):
    public_key = serialization.load_pem_public_key(public_key_bytes)
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# Função para descriptografar uma mensagem com a chave privada serializada
def decrypt_message(encrypted_message, private_key_str):
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

# Função para enviar mensagens
def send_messages(udp_socket, my_ip, my_port):
    global peer_addresses
    global public_keys

    while True:
        message_text = input("Digite as mensagens (ou 'exit' para sair): ")

        if message_text.lower() == 'exit':
            break

        # Gere um novo ID de mensagem
        message_id = str(uuid.uuid4())

        print(all_messages)

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
            public_key_bytes = public_keys.get(peer_addr)
            if public_key_bytes:
                encrypted_message = encrypt_message(message_json, public_key_bytes)
                udp_socket.sendto(encrypted_message, peer_addr)
            
            # Crie um dicionário para a confirmação em formato JSON
            confirmation_data = {
                "message_type": "Confirmation",
                "message_id": message_id
            }

            # Serializar a confirmação em JSON
            confirmation_json = json.dumps(confirmation_data)

            encrypted_confirmation = encrypt_message(confirmation_json, public_key_bytes)

            # Envie a confirmação
            udp_socket.sendto(encrypted_confirmation, peer_addr)

        message_save = ((my_ip, my_port), message_data)
        if message_save not in all_messages:
            all_messages.append(message_save)

# Função para receber mensagens em formato JSON
def receive_messages(udp_socket, private_key_str, public_key_str):
    global public_keys
    global confirmation_messages
    global parts_messages

    while True:
        try:
            data, addr = udp_socket.recvfrom(2048)

            try:
                data_decode = data.decode('utf-8')

                if "-----BEGIN PUBLIC KEY-----" in data_decode and "-----END PUBLIC KEY-----" in data_decode:
                    public_keys[addr] = data
                    udp_socket.sendto(public_key_str, addr)
                    pass  
            except:
                pass

            try:
                data_decrypt = decrypt_message(data, private_key_str)

                # Desserializar a mensagem JSON
                message_data = json.loads(data_decrypt)

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

                            # Adicione a mensagem à lista de mensagens
                            all_messages.append((addr, message_data)) #Tupla com endereço/porta e mensagem

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
                        print("SYNC:", message_data)
                        if "message_id" in message_data and "text" in message_data:
                            text_sync = message_data["text"]
                            if "Start sync" in text_sync: # Envia a lista de pares atualizada e a lista de mensagens
                                
                                print("STAR SYNC:", message_data)
                                # Envie a chave minha pública para o par que deseja sincronizar
                                for peer in peer_addresses:
                                    udp_socket.sendto(public_key_str, peer)
                                
                                # Id da lista de pares que será enviada
                                message_list_peers_id = str(uuid.uuid4())
                                # Tamanho da lista de pares que será enviada/quantidade de partes que será enviada
                                peers_size = len(peer_addresses)
                                # Envie a lista de pares atual
                                for peer in peer_addresses:
                                    send_sync(udp_socket, message_list_peers_id, "peer_addresses", peers_size, peer)

                                # Id da lista de mensagens que será enviada
                                message_list_message_id = str(uuid.uuid4())
                                # Tamanho da lista de mensagens que será enviada/quantidade de partes que será enviada
                                messages_size = len(all_messages)
                                # Envie a lista de mensagens atual
                                for message in all_messages:
                                    send_sync(udp_socket, message_list_message_id, "messages_list", messages_size, message)
                            
                        elif "message_id" in message_data and "content" in message_data and "size" in message_data and "part" in message_data:
                            
                            print("PART:", message_data)
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

                            # Serializar e criptografar a confirmação antes de enviar
                            confirmation_json = json.dumps(confirmation_message)
                            encrypted_confirmation = encrypt_message(confirmation_json, public_key_str)

                            udp_socket.sendto(encrypted_confirmation, addr)


            except Exception as e:
                pass
                

        except socket.timeout:
            pass
        except OSError as e:
            print(f"Ocorreu um erro de soquete: {str(e)}")
            break  # Encerre a thread quando ocorrer um erro de soquete

# Função para ordenar mensagens com base no "last_message_id"
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
    all_messages_sorted = order_messages(all_messages)
    print("\nTodas as mensagens: ")
    for message_data in all_messages_sorted:
        print(message_data)
    print()

# Função para limpar o terminal independente do S.O
def clear_terminal():
    current_os = platform.system()
    if current_os == "Windows":
        os.system("cls")
    else:
        os.system("clear")

# Função principal
def main():
    global peer_addresses

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

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.settimeout(2)  # Define um timeout de 2 segundos
    
    try:
        clear_terminal()

        my_ip = input("Digite seu endereço IP: ")
        my_port = int(input("Digite sua porta: "))

        udp_socket.bind((my_ip, my_port))

        # Iniciar a thread para receber mensagens
        receive_thread = threading.Thread(target=receive_messages, args=(udp_socket, private_key_str, public_key_bytes))
        receive_thread.start()

        # Iniciar a thread para lidar com as confirmações
        confirmation_thread = threading.Thread(target=handle_confirmations)
        confirmation_thread.start()

        # Iniciar a thread para sincronizar constantemente o sistema a cada "X" tempo
        confirmation_thread = threading.Thread(target=system_sync)
        confirmation_thread.start()

        # Iniciar a thread para sincronizar constantemente o sistema a cada "X" tempo
        confirmation_thread = threading.Thread(target=resend_unconfirmed_packets, args=(udp_socket,))
        confirmation_thread.start()

        # Envie a chave pública para todos os pares da lista
        for peer in peer_addresses:
            udp_socket.sendto(public_key_bytes, peer)
        
        # Informe que está online
        start_sync(udp_socket)

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
                clear_terminal()

            elif menu_main == 2:
                # Inicie a função send_messages na thread principal
                send_messages(udp_socket, my_ip, my_port)
                clear_terminal()

            elif menu_main == 3:
                read_messages()

            elif menu_main == 4:
                # Feche o socket ao sair
                udp_socket.close()
                exit()
    except socket.timeout:
        pass

if __name__ == "__main__":
    main()
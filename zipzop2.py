import socket
import threading
import uuid
import os
import platform
import json
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding

# Lista de pares participantes do grupo
peer_addresses = []  # Agora, os pares serão adicionados dinamicamente

# Dicionário para armazenar as chaves públicas dos pares
public_keys = {}

# Lista global para armazenar todas as mensagens
all_messages = []

# Dicionário para rastrear pacotes não confirmados e seus horários de envio
unconfirmed_packets = {}

# Dicionário para armazenar as mensagens de confirmação
confirmation_messages = {}

# Função para sincronizar mensagens
def sync_messages(udp_socket, message_text, my_ip, my_port):
    global peer_addresses

    # Gere um novo ID de mensagem
    message_id = str(uuid.uuid4())

    # Crie um dicionário para a mensagem em formato JSON
    message_data = {
        "message_type": "Sync",
        "message_id": message_id,
        "text": message_text,
        "sender_ip": my_ip,
        "sender_port": my_port
    }

    # Serializar a mensagem em JSON
    message_json = json.dumps(message_data)

    # Enviar a mensagem para todos os pares
    for peer_addr in peer_addresses:
        udp_socket.sendto(message_json.encode('utf-8'), peer_addr)

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

# Função para enviar mensagens em partes
def send_parts(udp_socket, id, content, size, part, my_ip, my_port):
    global peer_addresses

    # Crie um dicionário para a mensagem em formato JSON
    message_data = {
        "message_type": "SyncP",
        "message_id": id,
        "sender_ip": my_ip,
        "sender_port": my_port,
        "content": content,
        "size": size,
        "part": part
    }

    # Serializar a mensagem em JSON
    message_json = json.dumps(message_data)

    # Enviar a mensagem para todos os pares
    for peer_addr in peer_addresses:
        udp_socket.sendto(message_json.encode('utf-8'), peer_addr)

        # Adicione o pacote não confirmado ao dicionário
        unconfirmed_packets[id] = {"packet": message_json.encode('utf-8'), "address": peer_addr, "send_time": time.time()}

# Função para criptografar uma mensagem com a chave pública
def encrypt_message(message, public_key_str):
    public_key = serialization.load_pem_public_key(public_key_str.encode('utf-8'))
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# Função para descriptografar uma mensagem com a chave privada
def decrypt_message(encrypted_message, private_key_str):
    private_key = serialization.load_pem_private_key(private_key_str.encode('utf-8'), password=None)
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode('utf-8')

# Função para enviar mensagens em segundo plano
def send_messages(udp_socket, my_ip, my_port):
    global peer_addresses

    while True:
        message_text = input("Digite as mensagens (ou 'exit' para sair): ")

        if message_text.lower() == 'exit':
            break

        # Gere um novo ID de mensagem
        message_id = str(uuid.uuid4())

        # Verifique a posição da mensagem na lista
        if len(all_messages) == 0:
            last_message_id = "first"
        else:
            last_message_id = all_messages[-1]["message_id"]

        # Crie um dicionário para a mensagem em formato JSON
        message_data = {
            "message_type": "Message",
            "message_id": message_id,
            "sender_ip": my_ip,
            "sender_port": my_port,
            "text": message_text,
            "last_message_id": last_message_id
        }

        # Serializar a mensagem em JSON
        message_json = json.dumps(message_data)

        # Enviar a mensagem para todos os pares
        for peer_addr in peer_addresses:
            for peer, public_key_str in public_keys.items():
                if peer_addr == peer:
                    public_key = public_key_str
                    message_encrypt = encrypt_message(message_json, public_key)
                    udp_socket.sendto(message_encrypt, peer_addr)

            # Crie um dicionário para a confirmação em formato JSON
            confirmation_data = {
                "message_type": "Confirmation",
                "message_id": message_id,
                "sender_ip": my_ip,
                "sender_port": my_port,
                "last_message_id": last_message_id
            }

            # Serializar a confirmação em JSON
            confirmation_json = json.dumps(confirmation_data)

            # Envie a confirmação
            udp_socket.sendto(confirmation_json.encode('utf-8'), peer_addr)

        if message_data not in all_messages:
            all_messages.append(message_data)

# Função para juntar as partes das mensagens no local adequado
def join_parts(parts_messages, my_address):
    global peer_addresses
    global all_messages

    for package_id in parts_messages:
        package_list = parts_messages.get(package_id)
        if len(package_list) == package_list[0]["size"]:
            if package_list[0]["content"] == "peer_addresses":
                for package in package_list:
                    if package["part"] not in peer_addresses and package["part"] != my_address:
                        peer_addresses.append(tuple(package["part"]))

            elif package_list[0]["content"] == "messages_list":
                for package in package_list:
                    if package["part"] not in all_messages:
                        package["part"]["message_type"] = "Message"
                        all_messages.append(package["part"])
            return package_id

# Função para receber mensagens em formato JSON
def receive_messages(udp_socket, my_address, private_key_str, public_key_str):
    global peer_addresses
    global unconfirmed_packets
    global public_keys
    global confirmation_message

    parts_messages = {}

    while True:
        package_id = join_parts(parts_messages, my_address)
        if package_id is not None:
            parts_messages.pop(package_id)

        try:
            data, addr = udp_socket.recvfrom(1024)

            data_decrypt = decrypt_message(data, private_key_str)

            message_json = data_decrypt.decode('utf-8')

            # Desserializar a mensagem JSON
            message_data = json.loads(message_json)

            if "message_type" in message_data:
                message_type = message_data["message_type"]
                if message_type == "Message":
                    if "message_id" in message_data and "text" in message_data:
                        message_id = message_data["message_id"]

                        # Armazena a mensagem na lista desordenada
                        if message_data not in all_messages:
                            all_messages.append(message_data)

                        # Enviar confirmação de entrega da mensagem com o mesmo ID
                        if len(all_messages) != 0:
                            last_message_id = all_messages[-1]["message_id"]
                            confirmation_message = {
                                "message_type": "Confirmation",
                                "message_id": message_id,
                                "sender_ip": my_address[0],
                                "sender_port": my_address[1],
                                "last_message_id": last_message_id
                            }

                            udp_socket.sendto(json.dumps(confirmation_message).encode('utf-8'), addr)

                        else:
                            # Se não houver mensagens anteriores, envie "first" como last_message_id
                            confirmation_message = {
                                "message_type": "Confirmation",
                                "message_id": message_id,
                                "sender_ip": my_address[0],
                                "sender_port": my_address[1],
                                "last_message_id": "first"
                            }
                            udp_socket.sendto(json.dumps(confirmation_message).encode('utf-8'), addr)

                elif message_type == "Confirmation":
                    if "message_id" in message_data and "last_message_id" in message_data:
                        message_id = message_data["message_id"]

                        # Adiciona ao dicionário de mensagens de confirmação
                        confirmation_messages_exists = confirmation_messages.get(message_id)
                        # Salva a posição de cada mensagem na lista de cada par
                        if confirmation_messages_exists is not None:
                            confirmation_messages[message_id].append(message_data)
                        else:
                            confirmation_messages[message_id] = [message_data]

                        for message in all_messages:
                            if message["message_id"] == message_id:
                                if message_data["message_id"] in unconfirmed_packets:
                                    del unconfirmed_packets[message_data["message_id"]]

                elif message_type == "Sync":
                    if "message_id" in message_data and "text" in message_data:
                        text_sync = message_data["text"]
                        if " is online. Key: " in text_sync:
                            ip_value = text_sync.split(" is online. Key: ")[0]
                            public_key_str = text_sync.split(" is online. Key: ")[1]

                            public_keys[ip_value] = public_key_str
                            send_parts(udp_socket, str(uuid.uuid4()), "peer_addresses", len(peer_addresses), my_address[0], my_address[1])

                elif message_type == "SyncP":
                    if "message_id" in message_data and "size" in message_data and "part" in message_data:
                        message_id = message_data["message_id"]
                        # Verifica se existe uma chave para a parte da mensagem e cria caso não exista
                        message_part_exists = parts_messages.get(message_id)
                        if message_part_exists is not None:
                            parts_messages[message_id].append(message_data)
                        else:
                            parts_messages[message_id] = [message_data]

                        confirmation_message = {
                            "message_type": "Confirmation",
                            "message_id": message_id
                        }

                        addr_confirmation = (message_data["sender_ip"], message_data["sender_port"])
                        udp_socket.sendto(json.dumps(confirmation_message).encode('utf-8'), addr_confirmation)
        except:
            pass


# Função para ordenar mensagens com base no "last_message_id"
def order_messages(unordered_messages):
    def sort_key(message):
        last_message_id = message["last_message_id"]
        message_id = message["message_id"]

        try:
            last_message_id = uuid.UUID(last_message_id)
        except ValueError:
            last_message_id = uuid.UUID(int=0)

        try:
            message_id = uuid.UUID(message_id)
        except ValueError:
            message_id = uuid.UUID(int=0)

        if last_message_id == "first":
            return (uuid.UUID(int=0), message_id)
        elif last_message_id is None:
            return (uuid.UUID(int=1), message_id)
        return (last_message_id, message_id)

    first_messages = [message for message in unordered_messages if message["last_message_id"] == "first"]
    other_messages = [message for message in unordered_messages if message["last_message_id"] != "first"]
    ordered_messages = first_messages + sorted(other_messages, key=sort_key)

    return ordered_messages

# Função para ler todas as mensagens
def read_messages():
    all_messages_sorted = order_messages(all_messages)
    print("\nTodas as mensagens: ")
    for message_data in all_messages_sorted:
        print(f"-{message_data['sender_ip']}:{message_data['sender_port']} - {message_data['text']}")
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
        key_size=1024
    )

    # Exportar as chaves pública e privada
    private_key_str = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_key = private_key.public_key()
    public_key_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.settimeout(2)  # Define um timeout de 2 segundos

    try:
        clear_terminal()

        my_ip = input("Digite seu endereço IP: ")
        my_port = int(input("Digite sua porta: "))

        udp_socket.bind((my_ip, my_port))

        # Crie uma thread para receber mensagens
        receive_thread = threading.Thread(target=receive_messages, args=(udp_socket, (my_ip, my_port), private_key_str, public_key_str))
        receive_thread.start()

        # Informe que está online
        message_text = f"{my_ip}:{my_port} is online. Key: {public_key_str}"
        sync_messages(udp_socket, message_text, my_ip, my_port)

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
                    send_parts(udp_socket, str(uuid.uuid4()), "Message", 0, message_text, my_ip, my_port)
                clear_terminal()

            elif menu_main == 2:
                # Inicie a thread de envio de mensagens na thread principal
                send_messages(udp_socket, my_ip, my_port)
                clear_terminal()

            elif menu_main == 3:
                read_messages()

            elif menu_main == 4:
                # Feche o socket ao sair
                udp_socket.close()
                exit()
    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        udp_socket.close()

if __name__ == "__main__":
    main()
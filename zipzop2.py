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

# Lista de pares participantes do grupo
peer_addresses = [("192.168.0.127", 4444)]

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

        # Crie um dicionário para a mensagem em formato JSON
        message_data = {
            "message_type": "Message",
            "message_id": message_id,
            "sender_ip": my_ip,
            "sender_port": my_port,
            "text": message_text
        }

        # Serializar a mensagem em JSON
        message_json = json.dumps(message_data)

        # Enviar a mensagem para todos os pares
        for peer_addr in peer_addresses:
            print("PUBLIC KEY", public_keys[str(peer_addr)])
            encrypted_message = encrypt_message(message_json, public_keys[str(peer_addr)])
            udp_socket.sendto(encrypted_message, peer_addr)

# Função para receber mensagens em formato JSON
def receive_messages(udp_socket, my_address, private_key_str, public_key_str):
    global public_keys
    global confirmation_messages

    while True:
        try:
            data, addr = udp_socket.recvfrom(1024)

            print("CRIPTOGRAFADA", data)

            try:
                data_decrypt = decrypt_message(data, private_key_str)
                print("DESCRIPTOGRAFADA", data_decrypt)

                message_json = data_decrypt.decode('utf-8')

                print("DESCRIPTOGRAFADA json", message_json)
                # Desserializar a mensagem JSON
                message_data = json.loads(message_json)

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
                            all_messages.append(message_data)

                    elif message_type == "Confirmation":
                        if "message_id" in message_data:
                            message_id = message_data["message_id"]

                            # Adiciona ao dicionário de mensagens de confirmação
                            confirmation_messages_exists = confirmation_messages.get(message_id)
                            if confirmation_messages_exists is not None:
                                confirmation_messages[message_id].append(message_data)
                            else:
                                confirmation_messages[message_id] = [message_data]

                # Se a mensagem for uma chave pública
                elif "message_type" in message_data and message_data["message_type"] == "Public Key":
                    if "sender_ip" in message_data and "sender_port" in message_data and "text" in message_data:
                        sender_ip = message_data["sender_ip"]
                        sender_port = message_data["sender_port"]
                        public_key = message_data["text"]

                        # Adicione a chave pública ao dicionário public_keys com uma tupla como chave
                        public_keys[(sender_ip, sender_port)] = public_key

            except ValueError:
                message_json = data.decode('utf-8')
                # Desserializar a mensagem JSON
                message_data = json.loads(message_json)
                message_type = message_data["message_type"]
                if message_type == "Sync":
                    if "message_id" in message_data and "text" in message_data:
                        text_sync = message_data["text"]
                        if "is online" in text_sync: # Envia a lista de pares atualizada e a lista de mensagens
    
                            # Gere um novo ID de mensagem
                            public_key_id = str(uuid.uuid4())

                            public_key_text = f"Public key: {public_key_str}"

                            # Crie um dicionário para a mensagem em formato JSON
                            message_public_key = {
                                "message_type": "Sync",
                                "message_id": public_key_id,
                                "text": public_key_text
                            }

                            # Envie a chave pública para o par que informou que está online
                            for peer in peer_addresses:
                                udp_socket.sendto(json.dumps(message_public_key).encode('utf-8'), peer)
                            
                            # Pegar address do usuário que ficou online
                            ip_value = text_sync.split(" is online.")[0]

                            # Pegar a chave pública do usuário que ficou online
                            public_key = text_sync.split("Key: ")[1]
                            # Adicionar a chave do usuário que ficou online ao dicionário de chaves públicas
                            public_keys[ip_value] = public_key.rstrip('\n')

        except socket.timeout:
            pass
        except OSError as e:
            print(f"Ocorreu um erro de soquete: {str(e)}")
            break  # Encerre a thread quando ocorrer um erro de soquete

# Função para ordenar mensagens com base no "message_id"
def order_messages(unordered_messages):
    return sorted(unordered_messages, key=lambda x: x["message_id"])

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

        # Iniciar a thread para lidar com as confirmações
        confirmation_thread = threading.Thread(target=handle_confirmations)
        confirmation_thread.start()

        # Informe que está online
        message_text = f"{(my_ip, my_port)} is online. Key: {public_key_str}"
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
        #print(f"Error: {str(e)}")
        pass

if __name__ == "__main__":
    main()


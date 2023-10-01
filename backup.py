import socket
import threading
import uuid
import os
import platform
import json
from collections import Counter

# Cria um Lock
bloqued = threading.Lock()

# Lista global para armazenar todas as mensagens
all_messages = []
all_messages_sorted = []

confirmation_messages = {}

# Função para contar o votos em uma lista e retornar o vencedor
def counts_votes(votes):
    vote_count = Counter(votes) 
    max_votes = max(vote_count.values()) 
    lst = [i for i in vote_count.keys() if vote_count[i] == max_votes]
    winner = sorted(lst)[0]
    return winner

# Função para enviar mensagens em formato JSON
def send_messages(udp_socket, peer_addresses, message_ids):
    while True:
        message_text = input("Digite a mensagem a ser enviada (ou 'exit' para sair): ")
        
        if message_text.lower() == 'exit':
            break
        
        # Gere um novo ID de mensagem
        message_id = str(uuid.uuid4())
        message_ids.add(message_id)

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
            udp_socket.sendto(message_json.encode('utf-8'), peer_addr)

            last_message_id = "first" if len(all_messages) == 0 and len(all_messages_sorted) == 0 else all_messages[-1]["message_id"]

            # Crie um dicionário para a confirmação em formato JSON
            confirmation_data = {
                "message_type": "Confirmation",
                "message_id": message_id,
                "last_message_id": last_message_id
            }

            # Serializar a confirmação em JSON
            confirmation_json = json.dumps(confirmation_data)

            # Envie a confirmação
            udp_socket.sendto(confirmation_json.encode('utf-8'), peer_addr)

        # Armazenar mensagem na lista global
        sent_message = {
            "message_type": "Sent",
            "message_id": message_id,
            "sender": "You",
            "text": message_text
        }
        all_messages.append(sent_message)

# Função para receber mensagens em formato JSON
def receive_messages(udp_socket, message_ids, peer_addresses):
    while True:
        try:
            data, addr = udp_socket.recvfrom(1024)
            message_json = data.decode('utf-8')

            # Desserializar a mensagem JSON
            message_data = json.loads(message_json)

            if "message_type" in message_data:
                message_type = message_data["message_type"]
                if message_type == "Message":
                    if "message_id" in message_data and "text" in message_data:
                        message_id = message_data["message_id"]
                        message_text = message_data["text"]

                        # Enviar confirmação de entrega da mensagem com o mesmo ID
                        if len(all_messages) != 0:
                            last_message_id = all_messages[-1]["message_id"]
                            confirmation_message = {
                                "message_type": "Confirmation",
                                "message_id": message_id,
                                "last_message_id": last_message_id
                            }
                            udp_socket.sendto(json.dumps(confirmation_message).encode('utf-8'), addr)

                            # Armazenar mensagem na lista global
                            received_message = {
                                "message_type": "Received",
                                "message_id": message_id,
                                "sender": addr,
                                "text": message_text
                            }
                            all_messages.append(received_message)
                        else:
                            # Se não houver mensagens anteriores, envie "first" como last_message_id
                            confirmation_message = {
                                "message_type": "Confirmation",
                                "message_id": message_id,
                                "last_message_id": "first"
                            }
                            udp_socket.sendto(json.dumps(confirmation_message).encode('utf-8'), addr)

                            # Armazenar mensagem na lista global
                            received_message = {
                                "message_type": "Received",
                                "message_id": message_id,
                                "sender": addr,
                                "text": message_text
                            }
                            all_messages.append(received_message)

                elif message_type == "Confirmation":
                    if "message_id" in message_data and "last_message_id" in message_data:
                        message_id = message_data["message_id"]
                        position_message = message_data["last_message_id"]

                        # Adiciona ao dicionário de mensagens de confirmação
                        confirmation_messages_exists = confirmation_messages.get(message_id)
                        # Salva a posição de cada mensagem na lista de cada par
                        if confirmation_messages_exists is not None:
                            confirmation_messages[message_id].append(position_message)
                        else:
                            confirmation_messages[message_id] = [position_message]
                        try:
                            votes = confirmation_messages.get(message_id)  # Pega a lista de votos da mensagem a ser processada
                            voted_position = counts_votes(votes)
                            # voted_position = position_message

                            if voted_position == "first":  # Verifica se é a primeira mensagem
                                for message in all_messages:  # Verifica se a mensagem foi adicionada na lista de mensagens recebidas
                                    if message["message_id"] == message_id:
                                        all_messages_sorted.insert(0, message)

                            else:
                                for message in all_messages:
                                    if message["message_id"] == message_id:  # Verifica se a mensagem foi adicionada na lista de mensagens recebidas
                                        for message_sorted in all_messages_sorted:
                                            if message_sorted["message_id"] == voted_position:  # Encontra a posição de inserção
                                                position_isertion_message = all_messages_sorted.index(
                                                    message_sorted) + 1  # Pega o índice da mensagem que eu quero inserir
                                                all_messages_sorted.insert(position_isertion_message, message)
                        except ValueError:
                            print(f"Erro ao analisar o ID da confirmação: {message_id}")
                
                elif message_type == "SyncReq":
                    if "start" in message_data and "size" in message_data:
                        start = message_data["start"]
                        size = message_data["size"]
                        if start == "first" and size == 0:
                            # Gere um novo ID de mensagem
                            message_id = str(uuid.uuid4())
                            # message_ids.add(message_id)
                            size_package = len(all_messages)
                            for message in all_messages:

                                # Crie um dicionário para a mensagem em formato JSON
                                message_data = {
                                    "message_type": "SyncRes",
                                    "message_id": message_id,
                                    "size": size_package,
                                    "message": message
                                }

                                # Serializar a mensagem em JSON
                                message_json = json.dumps(message_data)
                                
                                # Enviar cada mensagem para todos os pares
                                for peer_addr in peer_addresses:
                                    udp_socket.sendto(message_json.encode('utf-8'), peer_addr) 

        except socket.timeout:
            pass

# Função para solicitar a lista de mensagens ordenada atual de cada par
def request_ordered_list(udp_socket, peer_addresses, my_ip):
    
    # Gere um novo ID de mensagem
    message_id = str(uuid.uuid4())

    # Crie um dicionário para a mensagem em formato JSON
    message_data = {
        "message_type": "SyncReq",
        "message_id": message_id,
        "start": "first",
        "size": 0
    }

    # Serializar a mensagem em JSON
    message_json = json.dumps(message_data)
    
    # Enviar a mensagem para todos os pares
    for peer_addr in peer_addresses:
        udp_socket.sendto(message_json.encode('utf-8'), peer_addr)
    
    udp_socket.settimeout(6) # Defina um timeout de 6s para o socket nessa função

    updated_lists = []
    # Criar a função que recebe vários pacotes e monta a lista de cada cliente.
    while True:
        try:
            # Receber a lista de mensagens atualizada de todos os pares e adiciona na lista com todas as respostas
            data, addr = udp_socket.recvfrom(1024)
            updated_list = data.decode('utf-8')

            updated_lists.append(updated_list)
        
        except socket.timeout:
            break
    
    # updated_list_winner = full_sync(updated_lists)
    return updated_list_winner

# Falta adicionar a confirmação para verificar se todas as partes chegaram com sucesso
def receive_parts(udp_socket, amout_parts):
    
    receive_parts_dict = {}
    while True:
        try:
            data, addr = udp_socket.recvfrom(1024)
            message_json = data.decode('utf-8')

            # Desserializar a mensagem JSON
            message_data = json.loads(message_json)
            if "message_type" in message_data and "sender" in message_data:
                message_type = message_data["message_type"]
                sender = message_data["sender"]
                message = message_data["message"]
                if message_type == "SyncRes":
                    sender_exists = receive_parts_dict.get(sender)
                    
                    #Cria uma chave no dicionário para cada remetente se não existir
                    if sender_exists is not None:
                                receive_parts_dict[sender] = []
                                receive_parts_dict[sender].append(message)
                    else:
                        receive_parts_dict[sender].append(message)
        except:
            pass

# Função para exibir mensagens de saída
def display_output():
    while True:
        with bloqued:
            user_input = input("Escolha uma opção:\n1. Enviar mensagem\n2. Ler mensagens\n3. Sair\nOpção: ")
        if user_input == '1':
            pass  # Continuar para enviar mensagens
        elif user_input == '2':
            read_messages()  # Chamar a função para ler mensagens
        elif user_input == '3':
            break
        else:
            with bloqued:
                print("Opção inválida. Tente novamente.")

# Função para ler todas as mensagens
def read_messages():
    with bloqued:
        print("\nTodas as mensagens:")
        for message_data in all_messages_sorted:
            print(f"{message_data['status']}. {message_data['text']} - De {message_data['sender']}")
        print()

# Função principal
def main():

    global all_messages_sorted
    
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.settimeout(2)  # Define um timeout de 2 segundos

    clear_terminal()

    my_ip = input("Digite seu endereço IP: ")
    my_port = int(input("Digite sua porta: "))

    udp_socket.bind((my_ip, my_port))

    num_peers = int(input("Quantos pares você deseja adicionar? "))
    peer_addresses = []

    for _ in range(num_peers):
        peer_ip = input("Digite o endereço IP do par: ")
        peer_port = int(input("Digite a porta do par: "))
        peer_address = (peer_ip, peer_port)
        peer_addresses.append(peer_address)
    
    clear_terminal()

    message_ids = set()

    # Crie threads para receber mensagens e exibir mensagens de saída
    receive_thread = threading.Thread(target=receive_messages, args=(udp_socket, message_ids, peer_addresses))
    output_thread = threading.Thread(target=display_output)
    
    # Defina a thread de exibição de saída como daemon para que ela possa ser interrompida quando o programa for encerrado
    output_thread.daemon = True

    receive_thread.start()
    output_thread.start()

    # Solicite as listas ordenadas e atualizadas dos pares conectados
    # all_messages_sorted = request_ordered_list()

    # Inicie a thread de envio de mensagens na thread principal
    send_messages(udp_socket, peer_addresses, message_ids)

    # Feche o socket ao sair
    udp_socket.close()

# Função para limpar o terminal independente do S.O
def clear_terminal():
    current_os = platform.system()
    if current_os == "Windows":
        os.system("cls")
    else:
        os.system("clear")

if __name__ == "__main__":
    main()
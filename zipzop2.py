import socket
import threading
import uuid
import os
import platform

# Cria um Lock
bloqued = threading.Lock()

# Lista global para armazenar todas as mensagens
all_messages = []
all_messages_sorted = []

# Função para receber mensagens
def receive_messages(udp_socket, message_ids):
    while True:
        try:
            data, addr = udp_socket.recvfrom(1024)
            message = data.decode('utf-8')
            if message.startswith("Message"):
                message_parts = message.split(" : ", 1)
                if len(message_parts) == 2:
                    message_id_str, text = message_parts
                    message_id_str = message_id_str.split(" ")[-1]
                    try:
                        #confirmation_message_id = uuid.UUID(message_id_str)
                        # Enviar confirmação de entrega da mensagem com o mesmo ID
                        if len(all_messages) != 0:
                            confirmation_message = f"Confirmation {message_id_str} : {all_messages[-1][-1]}" #Envia o id da última mensagem da lista confirmando a posição da ordenação
                            udp_socket.sendto(confirmation_message.encode('utf-8'), addr)
                            # Armazenar mensagem na lista global
                            all_messages.append((addr, text, "Received", message_id_str))  # Adiciona a etiqueta "Received"
                        else:
                            confirmation_message = f"Confirmation {message_id_str} : first" #Envia o id da última mensagem da lista confirmando a posição da ordenação
                            udp_socket.sendto(confirmation_message.encode('utf-8'), addr)
                            # Armazenar mensagem na lista global
                            all_messages.append((addr, text, "Received", message_id_str))  # Adiciona a etiqueta "Received"
                    except ValueError:
                        print(f"Erro ao analisar o ID da mensagem: {message_id_str}")
            elif message.startswith("Confirmation"):
                # Recebeu uma confirmação, extrai o ID
                message_parts = message.split(" ")
                if len(message_parts) == 4:
                    message_id_str = message_parts[1].strip()
                    position_message = message_parts[3].strip()
                    try:
                        if position_message == "first": #Verifica se é a primeira mensagem
                            for message in all_messages: #Verifica se a mensagem foi adicionada na lista de mensagens recebidas
                                if message[3] == message_id_str:
                                    all_messages_sorted.insert(0, message)
                        
                        for message in all_messages:
                            if message[3] == message_id_str: #Verifica se a mensagem foi adicionada na lista de mensagens recebidas
                                for message_sorted in all_messages_sorted:
                                    if message[3] == position_message: #Encontra a posição de inserção
                                        position_isertion_message = all_messages_sorted.index(message_sorted) + 1 #Pega o index da mensagem que eu quero inserir
                                        all_messages_sorted.insert(position_isertion_message, message)
                        #message_id = uuid.UUID(message_id_str)
                    except ValueError:
                        print(f"Erro ao analisar o ID da confirmação: {message_id_str}")
        except socket.timeout:
            pass

# Função para enviar mensagens para vários pares com confirmação
def send_messages(udp_socket, peer_addresses, message_ids):
    while True:

        message = input("Digite a mensagem a ser enviada (ou 'exit' para sair): ")
        
        if message.lower() == 'exit':
            break
        
        # Gere um novo ID de mensagem
        message_id = uuid.uuid4()
        message_ids.add(message_id)
        
        # Crie uma mensagem formatada com o ID
        message_with_id = f"Message {message_id} : {message}"
        
        # Enviar a mensagem para todos os pares
        for peer_addr in peer_addresses:
            udp_socket.sendto(message_with_id.encode('utf-8'), peer_addr)
        # Armazenar mensagem na lista global
        all_messages.append(("You", message, "Sent", message_id))  # Adiciona a etiqueta "Sent"

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
        print(all_messages)
        for message in all_messages:
            print(f"{message[2]}. {message[1]} - De {message[0]}")
        print()

# Função principal
def main():
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
    receive_thread = threading.Thread(target=receive_messages, args=(udp_socket, message_ids))
    output_thread = threading.Thread(target=display_output)
    
    # Defina a thread de exibição de saída como daemon para que ela possa ser interrompida quando o programa for encerrado
    output_thread.daemon = True

    receive_thread.start()
    output_thread.start()

    # Inicie a thread de envio de mensagens na thread principal
    send_messages(udp_socket, peer_addresses, message_ids)

    # Feche o socket ao sair
    udp_socket.close()

def clear_terminal():
    current_os = platform.system()
    if current_os == "Windows":
        os.system("cls")
    else:
        os.system("clear")

if __name__ == "__main__":
    main()
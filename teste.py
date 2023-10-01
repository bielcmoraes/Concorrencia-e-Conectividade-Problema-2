import socket
import threading
import uuid
import os
import platform
import json
from collections import Counter

# ...

# Função para enviar mensagens em segundo plano
def send_messages(udp_socket, peer_addresses):
    while True:
        message_text = input("Digite as mensagens (ou 'exit' para sair): ")

        if message_text.lower() == 'exit':
            break

        # Gere um novo ID de mensagem
        message_id = str(uuid.uuid4())

        # Verifique a posição da mensagem na lista
        if len(all_messages) == 0 and len(all_messages_sorted) == 0:
            last_message_id = "first"
        else:
            last_message_id = all_messages[-1]["message_id"]

        # Crie um dicionário para a mensagem em formato JSON
        message_data = {
            "message_type": "Message",
            "message_id": message_id,
            "text": message_text,
            "last_message_id": last_message_id
        }

        # Serializar a mensagem em JSON
        message_json = json.dumps(message_data)

        # Enviar a mensagem para todos os pares
        for peer_addr in peer_addresses:
            udp_socket.sendto(message_json.encode('utf-8'), peer_addr)

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

        all_messages.append(message_data)

# Função principal
def main():

    global all_messages_sorted
    global peer_addresses

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.settimeout(2)  # Define um timeout de 2 segundos

    clear_terminal()

    my_ip = input("Digite seu endereço IP: ")
    my_port = int(input("Digite sua porta: "))

    udp_socket.bind((my_ip, my_port))

    # Crie uma thread para receber mensagens
    receive_thread = threading.Thread(target=receive_messages, args=(udp_socket, peer_addresses))
    receive_thread.start()

    # Crie uma thread para informar que está online
    message_text = f"{my_ip} is online"
    sync_messages_thread = threading.Thread(target=sync_messages, args=(udp_socket, peer_addresses, message_text))
    sync_messages_thread.start()

    while True:
        print("[1] Para adicionar participantes a um grupo")
        print("[2] Para enviar mensagens")
        print("[3] Para visualizar mensagens")
        menu_main = int(input("[4] Para sair\n"))

        if menu_main == 1:
            num_peers = int(input("Quantos participantes deseja adicionar no grupo?"))

            for _ in range(num_peers):
                peer_ip = input("Digite o endereço IP do par: ")
                peer_port = int(input("Digite a porta do par: "))
                peer_address = (peer_ip, peer_port)
                peer_addresses.append(peer_address)

            # Enviar para todos os pares que alguém foi adicionado ao grupo
            for peer in peer_addresses:
                message_text = f"{my_ip} added {peer} to the group"
                create_group_thread = threading.Thread(target=sync_messages, args=(udp_socket, [peer], message_text))
                create_group_thread.start()

            break

        elif menu_main == 2:
            # Inicie a thread de envio de mensagens na thread principal
            send_messages_thread = threading.Thread(target=send_messages, args=(udp_socket, peer_addresses))
            send_messages_thread.start()

        elif menu_main == 3:
            pass
            # Inicie uma nova thread de visualização de mensagens
            # Defina a thread de exibição de saída como daemon para que ela possa ser interrompida quando o programa for encerrado

        elif menu_main == 4:
            # Feche o socket ao sair
            udp_socket.close()
            exit()

# ...

if __name__ == "__main__":
    main()

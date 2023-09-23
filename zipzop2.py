import socket
import threading
import uuid

# Função para receber mensagens
def receive_messages(udp_socket, message_ids):
    while True:
        data, addr = udp_socket.recvfrom(1024)
        message = data.decode('utf-8')
        if message.startswith("Message"):
            message_id, text = message.split(": ", 1)
            message_id = uuid.UUID(message_id.split(" ")[-1])

            # Enviar confirmação de entrega da mensagem com o mesmo ID
            confirmation_message = f"Confirmation {message_id}: Message delivered"
            udp_socket.sendto(confirmation_message.encode('utf-8'), addr)
            print(f"Mensagem de {addr[0]}:{addr[1]}: {text}")
        elif message.startswith("Confirmation"):
            # Recebeu uma confirmação, extrai o ID e imprime
            message_id, confirmation_text = message.split(": ", 1)
            message_id = uuid.UUID(message_id.split(" ")[-1])
            print(f"Confirmação de entrega recebida para a mensagem {message_id}")

# Função para enviar mensagens para vários pares com confirmação
def send_messages(udp_socket_messages, udp_socket_confirmations, peer_addresses, message_ids):
    while True:
        message = input("Digite a mensagem a ser enviada (ou 'exit' para sair): ")
        
        if message.lower() == 'exit':
            break
        
        # Gere um novo ID de mensagem
        message_id = uuid.uuid4()
        message_ids.add(message_id)
        
        # Crie uma mensagem formatada com o ID
        message_with_id = f"Message {message_id}: {message}"
        
        # Enviar a mensagem para todos os pares usando o socket de mensagens
        for peer_addr in peer_addresses:
            udp_socket_messages.sendto(message_with_id.encode('utf-8'), peer_addr)
            
        # Inicialize um contador para as confirmações
        confirmations = 0
        
        # Aguarde as confirmações de entrega usando o socket de confirmações
        while confirmations < len(peer_addresses):
            try:
                data, addr = udp_socket_confirmations.recvfrom(1024)
                confirmation_message = data.decode('utf-8')
                if confirmation_message.startswith("Confirmation"):
                    confirmation_id = uuid.UUID(confirmation_message.split(" ")[-1])
                    if confirmation_id == message_id:
                        confirmations += 1
                        print(f"Confirmação de entrega recebida de {addr[0]}:{addr[1]}")
            except socket.timeout:
                print("Tempo limite. Tentando novamente...")
        
        print("Mensagem entregue com sucesso para todos os pares.")

def main():
    # Crie dois sockets, um para mensagens e outro para confirmações
    udp_socket_messages = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket_confirmations = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    my_ip = input("Digite seu endereço IP: ")
    my_port_messages = int(input("Digite sua porta para mensagens: "))
    my_port_confirmations = 3333

    # Faça o bind dos sockets nas portas correspondentes
    udp_socket_messages.bind((my_ip, my_port_messages))
    udp_socket_confirmations.bind((my_ip, my_port_confirmations))

    num_peers = int(input("Quantos pares você deseja adicionar? "))
    peer_addresses = []

    for _ in range(num_peers):
        peer_ip = input("Digite o endereço IP do par: ")
        peer_port = int(input("Digite a porta do par: "))
        peer_address = (peer_ip, peer_port)
        peer_addresses.append(peer_address)

    message_ids = set()

    receive_thread = threading.Thread(target=receive_messages, args=(udp_socket_messages, message_ids))
    receive_thread.daemon = True
    receive_thread.start()

    send_thread = threading.Thread(target=send_messages, args=(udp_socket_messages, udp_socket_confirmations, peer_addresses, message_ids))
    send_thread.daemon = True
    send_thread.start()

    print("Digite 'exit' para sair do chat.")

    while True:
        user_input = input()
        if user_input.lower() == 'exit':
            break

    # Feche os sockets ao sair
    udp_socket_messages.close()
    udp_socket_confirmations.close()

if __name__ == "__main__":
    main()

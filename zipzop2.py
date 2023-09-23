import socket
import threading
import uuid

# Função para receber mensagens
def receive_messages(udp_socket, message_ids):
    while True:
        try:
            data, addr = udp_socket.recvfrom(1024)
            message = data.decode('utf-8')
            if message.startswith("Message"):
                message_id, text = message.split(": ", 1)
                message_id = uuid.UUID(message_id.split(" ")[-1])

                # Enviar confirmação de entrega da mensagem com o mesmo ID
                confirmation_message = f"Confirmation {message_id}: Message delivered"
                udp_socket.sendto(confirmation_message.encode('utf-8'), addr)
            elif message.startswith("Confirmation"):
                # Recebeu uma confirmação, extrai o ID
                message_id = uuid.UUID(message.split(":")[-1].strip())
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
        message_with_id = f"Message {message_id}: {message}"
        
        # Enviar a mensagem para todos os pares
        for peer_addr in peer_addresses:
            udp_socket.sendto(message_with_id.encode('utf-8'), peer_addr)
            
        # Inicialize um contador para as confirmações
        confirmations = 0
        
        # Aguarde as confirmações de entrega
        while confirmations < len(peer_addresses):
            try:
                data, addr = udp_socket.recvfrom(1024)
                confirmation_message = data.decode('utf-8')
                if confirmation_message.startswith("Confirmation"):
                    confirmation_id = uuid.UUID(confirmation_message.split(" ")[-1])
                    if confirmation_id == message_id:
                        confirmations += 1
            except socket.timeout:
                pass

# Função para exibir mensagens de saída
def display_output():
    while True:
        user_input = input()
        if user_input.lower() == 'exit':
            break

# Função principal
def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.settimeout(2)  # Define um timeout de 2 segundos

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

if __name__ == "__main__":
    main()
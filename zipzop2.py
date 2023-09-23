import socket
import asyncio
import uuid

# Função para receber mensagens
async def receive_messages(udp_socket, message_ids):
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
                print(f"Mensagem de {addr[0]}:{addr[1]}: {text}")
            elif message.startswith("Confirmation"):
                # Recebeu uma confirmação, extrai o ID e imprime
                message_id, confirmation_text = message.split(": ", 1)
                message_id = uuid.UUID(message_id.split(" ")[-1])
                print(f"Confirmação de entrega recebida para a mensagem {message_id}")
        except socket.timeout:
            print("")

# Função para enviar mensagens para vários pares com confirmação
async def send_messages(udp_socket, peer_addresses, message_ids):
    while True:
        message = await asyncio.to_thread(input, "Digite a mensagem a ser enviada (ou 'exit' para sair): ")
        
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
                        print(f"Confirmação de entrega recebida de {addr[0]}:{addr[1]}")
            except socket.timeout:
                print("Tempo limite de recepção. Tentando novamente...")
        
        print("Mensagem entregue com sucesso para todos os pares.")

async def main():
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

    # Crie uma tarefa asyncio para receber mensagens
    receive_task = asyncio.create_task(receive_messages(udp_socket, message_ids))
    
    # Crie uma tarefa asyncio para enviar mensagens
    send_task = asyncio.create_task(send_messages(udp_socket, peer_addresses, message_ids))

    print("Digite 'exit' para sair do chat.")

    await asyncio.gather(receive_task, send_task)

    # Feche o socket ao sair
    udp_socket.close()

if __name__ == "__main__":
    asyncio.run(main())

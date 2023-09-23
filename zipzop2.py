import socket
import threading
import time

# Função para receber mensagens
def receive_messages(udp_socket):
    while True:
        data, addr = udp_socket.recvfrom(1024)
        print(f"Mensagem de {addr[0]}:{addr[1]}: {data.decode('utf-8')}")
        # Enviar confirmação de entrega de mensagem
        confirmation_message = "Message delivered"
        udp_socket.sendto(confirmation_message.encode('utf-8'), addr)

# Função para enviar mensagens para vários pares com confirmação
def send_messages(udp_socket, peer_addresses):
    while True:
        message = input("Digite a mensagem a ser enviada: ")
        for peer_addr in peer_addresses:
            # Enviar mensagem
            udp_socket.sendto(message.encode('utf-8'), peer_addr)
            # Aguardar confirmação
            confirmation_received = False
            while not confirmation_received:
                try:
                    data, addr = udp_socket.recvfrom(1024)
                    if data.decode('utf-8') == "Message delivered":
                        print(f"Confirmação de entrega recebida de {addr[0]}:{addr[1]}")
                        confirmation_received = True
                except socket.timeout:
                    print(f"Tempo limite. Reenviando mensagem para {peer_addr[0]}:{peer_addr[1]}...")
                    udp_socket.sendto(message.encode('utf-8'), peer_addr)

def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    my_ip = input("Digite seu endereço IP: ")
    my_port = int(input("Digite sua porta: "))

    udp_socket.bind((my_ip, my_port))
    udp_socket.settimeout(5)  # Configura um tempo limite para receber confirmações

    num_peers = int(input("Quantos pares você deseja adicionar? "))
    peer_addresses = []

    for _ in range(num_peers):
        peer_ip = input("Digite o endereço IP do par: ")
        peer_port = int(input("Digite a porta do par: "))
        peer_address = (peer_ip, peer_port)
        peer_addresses.append(peer_address)

    receive_thread = threading.Thread(target=receive_messages, args=(udp_socket,))
    receive_thread.daemon = True
    receive_thread.start()

    send_thread = threading.Thread(target=send_messages, args=(udp_socket, peer_addresses))
    send_thread.daemon = True
    send_thread.start()

    print("Digite 'exit' para sair do chat.")

    while True:
        user_input = input()
        if user_input.lower() == 'exit':
            break

    udp_socket.close()

if __name__ == "__main__":
    main()
import socket
import threading
import time

# Função para receber mensagens
def receive_messages(udp_socket):
    while True:
        data, addr = udp_socket.recvfrom(1024)
        print(f"Mensagem de {addr[0]}:{addr[1]}: {data.decode('utf-8')}")
        # Enviar confirmação de recebimento ao remetente
        udp_socket.sendto("Confirmado".encode('utf-8'), addr)

# Função para enviar mensagens
def send_message(udp_socket, peer_ip, peer_port):
    while True:
        message = input()
        udp_socket.sendto(message.encode('utf-8'), (peer_ip, peer_port))
        # Aguardar confirmação de recebimento com timeout de 5 segundos
        udp_socket.settimeout(5)
        try:
            confirmation, _ = udp_socket.recvfrom(1024)
            if confirmation.decode('utf-8') == "Confirmado":
                print("Mensagem entregue com sucesso.")
        except socket.timeout:
            print("Tempo limite. Mensagem pode não ter sido entregue. Tentando novamente...")
        udp_socket.settimeout(None)  # Desativar timeout

def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    my_ip = input("Digite seu endereço IP: ")
    my_port = int(input("Digite sua porta: "))

    udp_socket.bind((my_ip, my_port))

    peer_ip = input("Digite o endereço IP do destinatário: ")
    peer_port = int(input("Digite a porta do destinatário: "))

    receive_thread = threading.Thread(target=receive_messages, args=(udp_socket,))
    receive_thread.daemon = True
    receive_thread.start()

    send_thread = threading.Thread(target=send_message, args=(udp_socket, peer_ip, peer_port))
    send_thread.daemon = True
    send_thread.start()

    print("Digite 'exit' para sair da conversa.")

    while True:
        user_input = input()
        if user_input.lower() == 'exit':
            break

    udp_socket.close()

if __name__ == "__main__":
    main()
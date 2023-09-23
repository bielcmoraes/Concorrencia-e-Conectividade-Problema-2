import socket
import threading

# Função para receber mensagens
def receive_messages(udp_socket):
    while True:
        try:
            data, addr = udp_socket.recvfrom(1024)
            print(f"Mensagem de {addr[0]}:{addr[1]}: {data.decode('utf-8')}")
        except:
            pass

# Função para enviar mensagens para todos os pares na lista de pares
def send_messages(udp_socket, peer_addresses):
    while True:
        message = input()
        for peer_addr in peer_addresses:
            udp_socket.sendto(message.encode('utf-8'), peer_addr)

def main():
    # Configuração do socket UDP
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Insira a porta em que deseja ouvir as mensagens
    listen_port = int(input("Digite a porta em que deseja ouvir: "))
    udp_socket.bind(('0.0.0.0', listen_port))

    # Insira o endereço IP do outro usuário (Peer 2)
    peer_ip = input("Digite o endereço IP do outro usuário (Peer 2): ")
    peer_port = int(input("Digite a porta do outro usuário (Peer 2): "))
    peer_address = (peer_ip, peer_port)

    # Crie uma lista para armazenar os endereços dos pares
    peer_addresses = [peer_address]

    # Inicia a thread para receber mensagens e passa o udp_socket como argumento
    receive_thread = threading.Thread(target=receive_messages, args=(udp_socket,))
    receive_thread.daemon = True
    receive_thread.start()

    # Inicia a thread para enviar mensagens e passa udp_socket e peer_addresses como argumentos
    send_thread = threading.Thread(target=send_messages, args=(udp_socket, peer_addresses))
    send_thread.daemon = True
    send_thread.start()

    print("Digite 'exit' para sair do chat.")

    # Mantém o programa em execução
    while True:
        user_input = input()
        if user_input.lower() == 'exit':
            break

    # Fecha o soquete ao sair
    udp_socket.close()

if __name__ == "__main__":
    main()
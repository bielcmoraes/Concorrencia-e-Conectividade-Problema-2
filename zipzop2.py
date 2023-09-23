import socket
import threading

# Função para receber mensagens
def receive_messages(udp_socket, peer_addresses):
    while True:
        data, addr = udp_socket.recvfrom(1024)
        if data.decode('utf-8') == "join":
            # Quando receber a mensagem "join" do grupo, enviar a mensagem de confirmação "joined"
            udp_socket.sendto("joined".encode('utf-8'), addr)
        else:
            print(f"Mensagem de {addr[0]}:{addr[1]}: {data.decode('utf-8')}")

# Função para criar um grupo
def create_group(udp_socket, listen_port, group_addresses):
    group_name = input("Digite o nome do grupo: ")
    group_ip = input("Digite o endereço IP do grupo: ")
    group_port = listen_port  # A porta do grupo é a mesma que a porta de escuta

    group_address = (group_ip, group_port)

    udp_socket.settimeout(50)
    udp_socket.sendto("join".encode('utf-8'), group_address)

    try:
        data, addr = udp_socket.recvfrom(1024)
        if data.decode('utf-8') == "joined":
            print(f"Grupo '{group_name}' criado. Agora você pode trocar mensagens no grupo.")
            udp_socket.settimeout(None)
            group_addresses[group_name] = group_address  # Adicione o grupo à lista de grupos

            # Envia mensagem de confirmação "joined" para o grupo
            for peer_addr in group_addresses.values():
                udp_socket.sendto("joined".encode('utf-8'), peer_addr)
        else:
            print("Erro ao criar o grupo.")
    except socket.timeout:
        print("Tempo limite. Não foi possível criar o grupo.")

# Função para trocar mensagens em um grupo
def chat_in_group(udp_socket, group_addresses):
    while True:
        user_input = input()
        if user_input.lower() == 'exit':
            break

        # Solicitar o nome do grupo ao usuário
        group_name = input("Digite o nome do grupo para enviar a mensagem: ")

        if group_name in group_addresses:
            group_address = group_addresses[group_name]
            udp_socket.sendto(user_input.encode('utf-8'), group_address)
        else:
            print(f"Grupo '{group_name}' não encontrado. Certifique-se de que o grupo foi criado.")

# Função principal
def main():
    # Configuração do socket UDP
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Insira a porta em que deseja ouvir as mensagens
    listen_port = int(input("Digite a porta em que deseja ouvir: "))
    udp_socket.bind(('0.0.0.0', listen_port))

    # Dicionário para armazenar os endereços dos grupos
    group_addresses = {}

    # Inicia a thread para receber mensagens no grupo geral
    receive_thread = threading.Thread(target=receive_messages, args=(udp_socket, group_addresses, "Grupo Geral"))
    receive_thread.daemon = True
    receive_thread.start()

    print("Digite 'exit' para sair do programa.")

    while True:
        user_input = input("Digite '1' para criar um grupo ou '2' para trocar mensagens em um grupo existente: ")
        if user_input == '1':
            create_group(udp_socket, listen_port, group_addresses)
        elif user_input == '2':
            chat_in_group(udp_socket, group_addresses)
        elif user_input.lower() == 'exit':
            break
        else:
            print("Comando inválido. Digite '1' ou '2'.")

    # Fecha o soquete ao sair
    udp_socket.close()

if __name__ == "__main__":
    main()
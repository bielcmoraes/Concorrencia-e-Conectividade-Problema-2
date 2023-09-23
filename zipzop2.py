import socket
import threading

# Função para receber mensagens
def receive_messages(udp_socket, peer_addresses):
    while True:
        data, addr = udp_socket.recvfrom(1024)
        if data.decode('utf-8') == "join":
            # Quando receber a mensagem "join" do grupo, enviar a mensagem de confirmação "joined"
            udp_socket.sendto("joined".encode('utf-8'), addr)  # Envie de volta ao remetente
            peer_addresses.append(addr)  # Adicione o remetente à lista de pares
        else:
            print(f"Mensagem de {addr[0]}:{addr[1]}: {data.decode('utf-8')}")

# Função para criar um grupo
def create_group(udp_socket, listen_port, group_addresses):
    group_name = input("Digite o nome do grupo: ")
    group_ip = input("Digite o endereço IP do grupo: ")
    group_port = listen_port  # A porta do grupo é a mesma que a porta de escuta

    group_address = (group_ip, group_port)

    udp_socket.settimeout(5)
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
def chat_in_group(udp_socket, group_addresses, my_address):
    while True:
        user_input = input()
        if user_input.lower() == 'exit':
            break

        # Solicitar o nome do grupo ao usuário
        group_name = input("Digite o nome do grupo para enviar a mensagem: ")

        if group_name in group_addresses:
            group_address = group_addresses[group_name]

            # Enviar a mensagem com confirmação
            confirm_received = False
            while not confirm_received:
                udp_socket.sendto(user_input.encode('utf-8'), group_address)
                print("Aguardando confirmação...")

                try:
                    data, addr = udp_socket.recvfrom(1024)
                    if data.decode('utf-8') == "confirmed":
                        print("Mensagem entregue com sucesso.")
                        confirm_received = True
                except socket.timeout:
                    print("Tempo limite. Tentando novamente...")

        else:
            print(f"Grupo '{group_name}' não encontrado. Certifique-se de que o grupo foi criado.")

# Função para adicionar um novo par ao grupo
def add_peer_to_group(udp_socket, group_addresses, my_address):
    group_name = input("Digite o nome do grupo para adicionar um par: ")

    if group_name in group_addresses:
        group_address = group_addresses[group_name]

        # Solicitar o endereço IP do par a ser adicionado
        peer_ip = input("Digite o endereço IP do par a ser adicionado: ")
        peer_port = group_address[1]  # A porta do par é a mesma do grupo

        peer_address = (peer_ip, peer_port)

        udp_socket.sendto("join".encode('utf-8'), peer_address)  # Solicitar ao par que se junte ao grupo

        try:
            data, addr = udp_socket.recvfrom(1024)
            if data.decode('utf-8') == "joined":
                print(f"Par {peer_ip}:{peer_port} adicionado ao grupo '{group_name}'.")
                group_addresses[group_name] = group_address  # Adicionar o par ao grupo
            else:
                print("Erro ao adicionar o par ao grupo.")
        except socket.timeout:
            print("Tempo limite. Não foi possível adicionar o par ao grupo.")
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

    print("Digite 'exit' para sair do programa.")

    while True:
        user_input = input("Digite '1' para criar um grupo, '2' para trocar mensagens em um grupo existente, "
                           "'3' para adicionar um par a um grupo ou '4' para sair: ")
        if user_input == '1':
            create_group(udp_socket, listen_port, group_addresses)
        elif user_input == '2':
            chat_in_group(udp_socket, group_addresses)
        elif user_input == '3':
            add_peer_to_group(udp_socket, group_addresses)
        elif user_input.lower() == '4':
            break
        else:
            print("Comando inválido. Digite '1', '2', '3' ou '4'.")

    # Fecha o soquete ao sair
    udp_socket.close()

if __name__ == "__main__":
    main()

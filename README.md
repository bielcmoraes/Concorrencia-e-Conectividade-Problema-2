<div align="center">
  <h1>
      Relatório do problema 2: ZapsZap
  </h1>

  <h3>
    Gabriel Cordeiro Moraes
  </h3>

  <p>
    Engenharia de Computação – Universidade Estadual de Feira de Santana (UEFS)
    Av. Transnordestina, s/n, Novo Horizonte
    Feira de Santana – BA, Brasil – 44036-900
  </p>

  <center>gcmorais66@gmail.com</center>

</div>

# 1. Introdução

Certamente! Os aplicativos de mensagens desempenham um papel fundamental no ambiente corporativo, transformando a forma como as organizações se comunicam e colaboram. Em um mundo empresarial cada vez mais dinâmico e globalizado, a capacidade de trocar informações de maneira rápida e eficiente é crucial para o sucesso de qualquer empreendimento. Os aplicativos de mensagens oferecem uma plataforma instantânea para a comunicação, quebrando as barreiras de tempo e espaço, permitindo que equipes se conectem instantaneamente, independentemente da localização geográfica.

# 2. Metodologia

### 2.1 - Sincronização


### 2.2 - Pacotes

1. **Pacote de mensagem**: { type: msg, time: ‘ ’,  id: ‘ ’, msg: ‘ ’, sender: { } }
   * type: string que identifica o tipo de pacote.
   * time: Timestamp do relógio lógico de quem enviou a mensagem.
   * id: String única que identifica a mensagem.
   * msg: A própria mensagem que foi enviada.
   * sender: Endereço de quem a enviou.

2. **Solicitação de sincronização**: { type: sync_clock, time: ‘ ’, sender: { } }
   

### 2.3 - Threads

1. **server_thread**: Iniciada como a primeira Thread do sistema, tem a função primordial de receber todos os pacotes que chegam, adicionando-os a uma fila para processamento posterior.
2. **handle_request_thread**: Operando sequencialmente à Thread anterior, a `handle_request_thread` acompanha a fila de pacotes e os trata de acordo com seus propósitos, garantindo uma abordagem sequencial no processamento.
3. **sync_clock_and_list_thread**: Esta Thread visa contatar todos os usuários ativos, realizando solicitações de sincronização de relógio lógico e mensagens. Seu propósito é manter uma coesão temporal e garantir a integridade das mensagens.
4. **receive_dict_sync_thread**: Responsável por receber as mensagens relacionadas à sincronização do sistema, esta Thread adiciona à lista de mensagens aquelas que estão ausentes e as organiza de maneira ordenada.
5. **write_prepare_message_thread**: Como sugere o nome, esta Thread se encarrega de capturar as mensagens escritas pelo usuário e prepará-las para serem enviadas aos demais, garantindo a eficiência na comunicação.
6. **sync_active_thread**: Por fim, a última Thread iniciada é responsável por realizar a sincronização a cada 10 segundos das mensagens entre todos os usuários ativos, contribuindo para uma experiência contínua e atualizada.

### 2.4 - Criptografia



# 3. Resultados


# 4. Conclusão


# Referências

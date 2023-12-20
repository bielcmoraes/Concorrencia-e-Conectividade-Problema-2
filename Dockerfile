# Use uma imagem base Python
FROM python:3.11

# Define o diretório de trabalho no contêiner
WORKDIR /app

# Copia os arquivos do projeto para o contêiner
COPY . .

# Comando para executar o aplicativo quando o contêiner iniciar
CMD ["python3", "chat.py"]
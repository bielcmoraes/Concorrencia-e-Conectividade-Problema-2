
#  implementar envio de chave pública quando um membro do grupo ficar online
import sys
import uuid

message_data = {
            "message_type": "Message",
            "message_id": str(uuid.uuid4()),
            "sender": "192.168.0.121",
            "text": text,
            "last_message_id": str(uuid.uuid4())
        }
message_size = sys.getsizeof(message_data)

print(f"Tamanho do pacote é: {message_size} bytes")
print(f"Tamanho da área de texto é: {len(text)} caracteres")
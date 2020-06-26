import lamport
import hashlib
import secrets

#Usaremos la funcion hash SHA-256.
def sha256(msg):
	hash = hashlib.sha256()
	hash.update(msg)
	return hash.digest()

# Usaremos la misma función como función one-way (resistente a la preimagen)
def ow256(x):
	return sha256(x)

#---------------------------------------
#                EMISOR
#---------------------------------------

l = lamport.LDOTS(256,sha256,ow256)

l.generate_keys()

signature = l.sign("texto critico que necesito enviar".encode('utf-8'))
pubkey = l.pubK

#---------------------------------------
#                RECEPTOR
# El receptor sabe la clave publica del emisor,
# y recibe el mensaje con la firma.
#---------------------------------------

otro = lamport.LDOTS(256,sha256,ow256,pubkey)

print(otro.verify("texto critico que necesito enviar".encode('utf-8'),signature)) # Devuelve True, el mensaje es autentico!
print(otro.verify("estoy intentando falsificar un documento con la misma firma!".encode('utf-8'),signature)) # Devuelve False, este mensaje no es autentico!
print(otro.verify("texto critica que necesito enviar".encode('utf-8'),signature)) # Devuelve False, aun habiendo cambiado una letra, el mensaje ya no es autentico.
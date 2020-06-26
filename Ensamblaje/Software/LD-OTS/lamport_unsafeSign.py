import lamport
import hashlib
import pickle

n = 32

#Usaremos la funcion hash SHA-256 utilizando solo los 32 primeros bits (4 primeros bytes).
def sha256(msg):
    hash = hashlib.sha256()
    hash.update(msg)
    return hash.digest()[:n//8]
    
l = lamport.LDOTS(n,sha256,sha256)
l.import_keys(public="test_"+str(n)+".PUK",private="test_"+str(n)+".PRK")

firma1 = l.sign("Documento para firmar 1".encode("utf-8"))
firma2 = l.sign("Documento para firmar 2".encode("utf-8"))

f1 = open("firma1_"+str(n)+".SIG","wb")
f2 = open("firma2_"+str(n)+".SIG","wb")

f1.write(pickle.dumps(firma1))
f2.write(pickle.dumps(firma2))

f1.close()
f2.close()
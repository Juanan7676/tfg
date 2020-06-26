import lamport
import hashlib

n = 32

#Usaremos la funcion hash SHA-256 utilizando solo los n primeros bits (n/8 primeros bytes).
def sha256(msg):
    hash = hashlib.sha256()
    hash.update(msg)
    return hash.digest()[:n//8]
    
l = lamport.LDOTS(n,sha256,sha256)
l.generate_keys()
l.export_keys("test_"+str(n),"test_"+str(n))
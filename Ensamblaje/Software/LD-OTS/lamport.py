import secrets
import pickle

def bitfield(n):
    return [1 if digit=='1' else 0 for digit in bin(n)[2:]]

# Convierte un array de bytes a un array de bits.
def bytestobits(arr):
    l = []
    for k in arr:
        bits = bitfield(k)
        l.append([0]*(8-len(bits))+bits)
    return [ i for k in l for i in k]

class LDOTS:
    # Inicializa la clase. Especificar el numero de bits que devuelve la funcion hash y la funcion de ida (n), la funcion
    # hash y la funcion de ida correspondientes y si queremos verificar usando una clave publica, se pasa como ultimo parametro.
    def __init__(self, n, hash_f, ow_f, pubK = None):
        self.n = n
        self.hash_f = hash_f
        self.ow_f = ow_f
        
        if pubK:
            self.pubK = pubK
            self.privK = None
    
    # Genera un par de claves aleatorias criptograficamente seguras
    def generate_keys(self):
        self.privK = [ ( secrets.randbits(self.n).to_bytes(self.n//8,'big'),secrets.randbits(self.n).to_bytes(self.n//8,'big')) for k in range(self.n) ]
        self.pubK = [ (self.ow_f(k[0]),self.ow_f(k[1])) for k in self.privK ]
    
    # Exporta las claves en los dos ficheros indicados
    def export_keys(self, pubName, privName):
        pubFile = open(pubName+".PUK","wb")
        pubFile.write(pickle.dumps(self.pubK))
        pubFile.close()
        
        privFile = open(privName+".PRK","wb")
        privFile.write(pickle.dumps(self.privK))
        privFile.close()
        
    def import_pubK(self,name):
        file = open(name,"rb")
        self.pubK = pickle.loads(file.read())
        file.close()
    
    def import_privK(self,name):
        file = open(name,"rb")
        self.privK = pickle.loads(file.read())
        file.close()
    
    def import_keys(self,public,private):
        self.import_pubK(public)
        self.import_privK(private)
    
    # Aunque va en contra del protocolo (solo se debe firmar una vez con la msima clave privada), si
    # queremos reutilizar la clave privada para volver a firmar, llamar a este metodo (calcula tambien la clave publica)
    def set_privK(self,privK):
        self.privK = privK
        self.pubK = [ (self.ow_f(k[0]),self.ow_f(k[1])) for k in self.privK ]
    
    # Firma el mensaje especificado.
    # La firma puede pasarse directamente al metodo verify(). Es necesario contar con la clave privada para usar este metodo.
    def sign(self,msg):
        if self.privK:
            d = bytestobits(self.hash_f(msg))
            return [ self.privK[j][d[j]] for j in range(self.n) ]
        else:
            raise Exception("No private key is provided; use generate_keys() method to generate one!")
    
    # True si el mensaje es autentico, False si no lo es
    # Es necesario haber inicializado esta clase con la clave publica del emisor.
    def verify(self,msg,signature):
        if self.pubK:
            d = bytestobits(self.hash_f(msg))
            
            for j in range(self.n):
                if self.ow_f(signature[j]) != self.pubK[j][d[j]]: return False
            
            return True
        else:
            raise Exception("No public key is provided!")
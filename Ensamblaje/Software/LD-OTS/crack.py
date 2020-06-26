import lamport
import hashlib
import pickle
import time

class TextoVariable:
    
    def __init__(self,numpos,baseStr):
        self.bstr = baseStr
        self.n = numpos
        self.options = []
        for k in range(numpos):
            self.options.append((2,("","")))
        self.curr = [0 for k in range(self.n)]
    
    def setOption(self,index,options):
        self.options[index] = (len(options),options)
    
    def nextString(self):
        for k in range(self.n):
            if self.curr[k] < (self.options[k][0] - 1):
                self.curr[k] += 1
                break
            else:
                self.curr[k]=0
                if k==self.n - 1:
                    return ""
        
        ret = self.bstr
        for k in range(self.n):
            ret = ret.replace("~", self.options[k][1][self.curr[k]],1)
        return ret

    def iterator(self):
        str = self.nextString()
        while (str!=""):
            yield str
            str = self.nextString()
    def reset(self):
        self.curr = [0 for k in range(self.n)]

n = 32

def sha256(msg):
    hash = hashlib.sha256()
    hash.update(msg)
    return hash.digest()[:n//8]
    
l = lamport.LDOTS(n,sha256,sha256)
l.import_pubK("test_"+str(n)+".PUK")

msg1 = "Documento para firmar 1".encode("utf-8")
dig1 = lamport.bytestobits(sha256(msg1))
sig1 = pickle.load(open("firma1_"+str(n)+".SIG","rb"))

msg2 = "Documento para firmar 2".encode("utf-8")
dig2 = lamport.bytestobits(sha256(msg2))    
sig2 = pickle.load(open("firma2_"+str(n)+".SIG","rb"))

# Texto a falsificar:
# ------------------------------------------------------------------------
# Este {documento|papel|informe} esta {pensado|ideado|hecho} {para|con el fin de|con el objetivo de}
# ser {usado|utilizado} con {fines|objetivos} {maliciosos|malignos|no deseados}.
# Lo {lograremos|conseguiremos|haremos} {poniendo|añadiendo|usando} {muchas|multitud de|un monton de}
# palabras {parecidas|similares|sinonimas} para {obtener|tener|conseguir} {muchas|multitud de} opciones
# de donde {elegir|escoger}. {Pocas|Muy pocas} palabras, y no {seremos capaces de|podremos} {obtener|generar|crear} un documento {falso|falsificado}.
# {Firmado|Atentamente|Cordialmente|Saludos cordiales}, Alice.
# -------------------------------------------------------------------------
# Posibles textos: 3^10 * 2^7 * 4 = 30.233.088 textos

msgGen = TextoVariable(18,"Este ~ esta ~ ~ ser ~ con ~ ~. Lo ~ ~ ~ palabras ~ para ~ ~ opciones de donde ~. ~ palabras, y no ~ ~ un documento ~. ~, Alice. ")
msgGen.setOption(0,("documento","papel","informe"))
msgGen.setOption(1,("pensado","ideado","hecho"))
msgGen.setOption(2,("para","con el fin de","con el objetivo de"))
msgGen.setOption(3,("usado","utilizado"))
msgGen.setOption(4,("fines","objetivos"))
msgGen.setOption(5,("maliciosos","malignos","no deseados"))
msgGen.setOption(6,("lograremos","conseguiremos","haremos"))
msgGen.setOption(7,("poniendo","añadiendo","usando"))
msgGen.setOption(8,("muchas","multitud de","un monton de"))
msgGen.setOption(9,("parecidas","similares","sinonimas"))
msgGen.setOption(10,("obtener","tener","conseguir"))
msgGen.setOption(11,("muchas","multitud de"))
msgGen.setOption(12,("elegir","escoger"))
msgGen.setOption(13,("Pocas","Muy pocas"))
msgGen.setOption(14,("seremos capaces de","podremos"))
msgGen.setOption(15,("obtener","generar","crear"))
msgGen.setOption(16,("falso","falsificado"))
msgGen.setOption(17,("Firmado","Atentamente","Cordialmente","Saludos cordiales"))

#------------------------------------
# Metodo 1: Fuerza bruta conociendo 1 sola firma
# -----------------------------------

#start = time.time()

#k=1
#for msg in msgGen.iterator():
#    digest = lamport.bytestobits(sha256(msg.encode('utf-8')))
#    if (digest == dig1):
#        print("DOCUMENTO FALSIFICADO! -------------")
#        print(msg)
#        print("Comprobacion: " + str(l.verify(msg.encode('utf-8'),sig1)))
#        break
#    k += 1
#
#print(str(k)+" documentos probados.")
#print("%s segundos" % (time.time() - start))
#print("")

#------------------------------------
# Metodo 2: 2 firmas distintas
# -----------------------------------

msgGen.reset()

start = time.time()

cont = 1
for msg in msgGen.iterator():
    digest = lamport.bytestobits(sha256(msg.encode('utf-8')))
    mysig = []
    for k in range(len(digest)):
        if digest[k]==dig1[k]:
            mysig.append(sig1[k])
        elif digest[k]==dig2[k]:
            mysig.append(sig2[k])
        else:
            break
    if len(mysig)==len(sig1):
        print("DOCUMENTO FALSIFICADO! -------------")
        print(msg)
        print("Comprobacion: " + str(l.verify(msg.encode('utf-8'),mysig)))
        break
    cont += 1

print(str(cont)+" documentos probados.")
print("%s segundos" % (time.time() - start))
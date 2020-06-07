from Crypto.PublicKey import ECC
from Crypto.Hash import keccak
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
import base64
def generatekey(groupid,x):
        key = ECC.generate(curve='P-256')
        pkey=key.public_key()
        fa=""+groupid+'.pem'
        fap="p"+groupid+'.pem'
        if(x==True):
            f=open(fa,'wt')
            f.write(key.export_key(format='PEM'))
            f.close()
            f=open(fap,'wt')
            f.write(pkey.export_key(format='PEM'))
            f.close()
    	#f = open('myprivatekey.pem','rt')
    	#key = ECC.import_key(f.read())
        return key.export_key(format='PEM'),pkey.export_key(format='PEM')
  
def generateticket(objectid,groupid,pubaddr):
        #print(pubaddr)
        signmsg=objectid+groupid+pubaddr
    	#h=keccak.new(digest_bits=512)
    	#h.update(str.encode(signmsg))
        h=SHA256.new(str.encode(signmsg))
        key = ECC.import_key(open(groupid+'.pem','rt').read())
        signer=DSS.new(key,'fips-186-3')
        signature=signer.sign(h)
        #s = signature.encode('ascii')
        #sb = base64.b64encode(s)
        #signature_enc = str(base64.b64encode(signature))
        print(signature)
        print(signmsg)
        #print("a\n")
        #print(signature_enc)
        #return signature_enc
        #return sb
        return signature

def verifyticket(groupid,objectid,pubaddr,sign):
        #print(sign)        
        #sign= str(base64.b64decode(sign))
        #print("a\n")
        #sign = sign.decode('ascii')
        print(sign)
        signmsg=objectid+groupid+pubaddr
        print(signmsg)
        #h=keccak.new(digest_bits=512)
        #h.update(str.encode(signmsg))
        h=SHA256.new(str.encode(signmsg))
        key = ECC.import_key(open("p"+groupid+'.pem','rt').read())
        verifier=DSS.new(key,'fips-186-3')
        try:
            verifier.verify(h, sign)
            return True
        except ValueError:
            return False

mkey,mpkey=generatekey("101",True);
key,pkey=generatekey("",False);
sign=generateticket("1","101",pkey)
print(verifyticket("101","1",pkey,sign))


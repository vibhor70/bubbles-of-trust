from Crypto.PublicKey import ECC
from Crypto.Hash import keccak
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

def generatekey(x):
	key = ECC.generate(curve='P-256')
	pkey=key.public_key()
	if(x==True):
		f=open('mprivatekey.pem','wt')
		f.write(key.export_key(format='PEM'))
		f.close()
		f=open('mpublickey.pem','wt')
		f.write(pkey.export_key(format='PEM'))
		f.close()
	#f = open('myprivatekey.pem','rt')
	#key = ECC.import_key(f.read())
	return key,pkey
  
def generateticket(self,objectid,groupid,followerpubkey):
        x=keccak.new(digest_bits=512)
        x.update(str.encode(followerpubkey))
        pubaddr=x.hexdigest()
        #print(pubaddr)
        signmsg=objectid+groupid+pubaddr
    	#h=keccak.new(digest_bits=512)
    	#h.update(str.encode(signmsg))
        h=SHA256.new(str.encode(signmsg))
        key = ECC.import_key(open(groupid+'.pem','rt').read())
        signer=DSS.new(key,'fips-186-3')
        signature=signer.sign(h)
        signature_enc = str(base64.b64encode(signature))
        return pubaddr,signature_enc
    
def verifyticket(self,groupid,objectid,pubaddr,sign):
        sign= str(base64.b64decode(sign))
        signmsg=objectid+groupid+pubaddr
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

mkey,mpkey=generatekey(True);
key,pkey=generatekey(False);
sign=generateticket("1","group1",pkey)
print(verifyticket("1","group1",pkey,sign))


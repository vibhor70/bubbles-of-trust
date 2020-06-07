import requests
def getchain():
	Url="http://127.0.0.1:5000/get_chain"
	Params={'':""}
	r=requests.get(url=Url,params=Params)
	data=r.json()
	print(data)

def addtransaction():
	Url="http://127.0.0.1:5000/add_transaction"
	Params={'Category':"Master",'Master':"samsung",'GroupId':"101",'ObjectId':"object1"}
	r=requests.post(url=Url,json=Params)
	data=r.text
	print(data)

def connectnode():
	Url="http://127.0.0.1:5000/connect_node"
	Params={'nodes':"[127.0.0.1:5001]"}
	r=requests.post(url=Url,json=Params)
	data=r.text
	print(data)


def mineblock():
	Url="http://127.0.0.1:5000/mine_block"
	Params={'':""}
	r=requests.get(url=Url,params=Params)
	data=r.json()
	print(data)
def replacechain():
	Url="http://127.0.0.1:5000/replace_chain"
	Params={'':""}
	r=requests.get(url=Url,params=Params)
	data=r.json()
	print(data)

addtransaction()
getchain()
mineblock()
#connectnode()
replacechain()	

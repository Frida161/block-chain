import socket  # 导入模块
from threading import Thread
import time
import queue

import hashlib, time
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import json

class transaction():
    def __init__(self, key, fromAddress, toAddress, amount):
        global signature
        self.fromAddress = fromAddress
        self.toAddress = toAddress
        self.amount = amount
        signature = None
        self.key = key
        if not isinstance(self.key,str):
            self.signTransaction(key)
        else:
            signature = 'pass'
        self.isValid()
         
    def calculateHash(self):
        return SHA256.new((str(self.fromAddress) + str(self.toAddress) + self.amount).encode())
    
    def signTransaction(self, signingkey):
        global signature
        hasher = self.calculateHash()
        signer = DSS.new(signingkey, 'fips-186-3')
        signature = signer.sign(hasher)
    
    def isValid(self):
        global signature
        if isinstance(self.key, str):  #系统发放的矿工奖励跳过验证
            return True
        
        try:
            verifer = DSS.new(self.key.public_key(), 'fips-186-3')   #使用公钥创建校验对象
            hasher = self.calculateHash()
            verifer.verify(hasher, signature)
            self.key = str(self.key)
            #self.signature = str(self.signature)
            # The signnature is valid.
            return True
        except(ValueError, TypeError):
            print('The signature is not valid.')
            return False
  
class Block:
    def __init__(self, timestamp = '', transaction = '', previousHash = ''):
        self.timestamp = timestamp
        self.transaction = transaction
        self.previousHash = previousHash
        self.nonce = 0
        self.hash = self.calculateHash()
    
    def calculateHash(self):
        if isinstance(self.transaction, str):
            transaction = self.transaction
        else:
            transaction = [str(i.fromAddress) + str(i.toAddress) + i.amount for i in self.transaction]
        return hashlib.sha256((self.previousHash + self.timestamp + ''.join(transaction) + str(self.nonce)).encode()).hexdigest()
    
    def validateTransactions(self):
        if isinstance(self.transaction, str):
            return True
        for transaction in self.transaction:
            if not transaction.isValid():
                print('invalid transaction found in transactions(发现异常交易)')
                return False
        return True

    def mineBlock(self, difficulty):
        while self.hash[0: difficulty] != '0' * difficulty:
            self.nonce = self.nonce + 1
            self.hash = self.calculateHash()
        
        print('Block mined:', self.hash)

class Blockchain:
    def __init__(self):
        self.chain = [self.createGenesisBlock()]
        self.difficulty = 2
        self.transactionPool = []
        self.miningReward = 50

    def createGenesisBlock(self):
        return Block( '25/5/2020', 'Genesis Block', '0')
    
    def getLatestBlock(self):
        return self.chain[len(self.chain)-1]
    
    def mineTransactionPool(self, miningRewardAddress):  #发放奖励
        miningRewardTransaction = transaction('key', 'system', miningRewardAddress, str(self.miningReward))
        self.transactionPool.append(miningRewardTransaction)
        newblock = Block(str(time.time()), self.transactionPool)
        newblock.previousHash = self.getLatestBlock().hash
        newblock.mineBlock(self.difficulty)
        self.chain.append(newblock)
        self.transactionPool = []
    
    def addtransaction(self, transaction):
        if not transaction.isValid():
            raise Exception('The transaction is invalid')
        self.transactionPool.append(transaction)
        #print('The transaction is valid')
    
    def getBalanceOfAddress(self, address):
        balance = 0
        for index in range(1, len(self.chain)):
            for transaction in self.chain[index].transaction :
                if not isinstance(transaction.fromAddress, str) and transaction.fromAddress == address:
                    balance = balance - float(transaction.amount)
                
                if transaction.toAddress == address:
                    balance = balance + float(transaction.amount)
        return balance
    
    def isChainvalid(self):
        for i in range(1, len(self.chain)):
            currentBlock = self.chain[i]
            previousBlock = self.chain[i - 1]

            for index in range(1, len(self.chain)):
                if not self.chain[index].validateTransactions():
                    return False 

            if currentBlock.hash != currentBlock.calculateHash():
                print('transaction has been modified(数据篡改)')
                return False
            if currentBlock.previousHash != previousBlock.hash:
                print('The blockchain is broken（区块链断裂）')
                return False
        return True
    
CTcoin = Blockchain()
privatekeysender = ECC.generate(curve = 'P-256')  #转账者私钥
publickeysender = privatekeysender.public_key()   #转账者公钥

class ServerThread(Thread):
    """服务线程，进行消息的接收"""
    def __init__(self, my_queue):  # 初始化线程
        super().__init__()
        self._ip_address_list = []   # 保存连接过的ip地址，便于下次连接
        self._ip_address = get_host_ip()  # 获取当前主机IP地址
        self._sever = socket.socket()  # 初始化socket对象，默认参数 family=AF_INET,(IPv4),type=SOCK_STREAM(TCP)
        self._sever.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  #允许重复的捆绑
        self._my_queue = my_queue  # 初始化消息队列

    def run(self):
        global client, address
        signal = False
        self._sever.bind((self._ip_address, 5678))  # 绑定IP和端口
        self._sever.listen(512)  # 开始监听
        print("本地" + self._ip_address + "正在监听等待连接。。。")
        while True:
            signal = False
            try:
                time.sleep(1)  #推迟执行的秒数
                client, address = self._sever.accept()  # 有接入时获取客户端对象
                self._ip_address_list.append(address)  # 添加当前客户端到列表中
                message = client.recv(1024) # 并获取发送来的消息
                if message[0:1] == b'\x11' :
                    self._my_queue.put("来自" + address[0] + '：' + message[1:].decode('utf-8'))  # 发送给消息队列中
                    print("来自" + address[0] + '：' + client.recv(512).decode('utf-8'))
                elif message[0:1] == b'1':
                    receive_block(message[1:].decode('utf-8'))
                    print(CTcoin.chain)
                elif message[0:1] == b'2':
                    receive_transaction(message[1:].decode('utf-8'))
                    self._my_queue.put('某人已发起新的交易，交易池已更新')
                    print(CTcoin.transactionPool)
                elif message[0:1] == b'3':
                    self._my_queue.put(message[1:].decode('utf-8'))
                    CTcoin.transactionPool = []
                elif message.decode('utf-8') == 'a':
                    self._my_queue.put('某人请求下载区块信息')
                self._is_send = False  # 发送完成后初始化参数为不发送
                time.sleep(2)
            except Exception as e:  # 处理一异常
                print(e)

    @property  #装饰器，像属性一样调用
    def ip_address(self):  # ip当前的get方法
        return self._ip_address

    @property
    def ip_address_list(self):  # IP列表的get方法
        return self._ip_address_list


class ClientThread(Thread):
    """客户端的线程"""
    def __init__(self):  # 初始化客户端线程
        super().__init__()
        self._ip_address = ''
        self._is_send = False  # 是否执行消息发送操作
        self._message = ''
            
    def run(self):
        global order
        while True:
            if self._is_send:  # 如果需要发送消息
                try:
                    client = socket.socket()  # 客户端Socket对象
                    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    client.connect(self._ip_address)  # 需要链接的服务器地址
                    if order == '1' or '2' or '3' or '4':
                        client.send(self._message)  # 需要发送的消息
                    self._is_send = False  # 发送完成后初始化参数为不发送
                    time.sleep(2)
                except Exception as e:  # 异常获取
                    print(e)  # 输出异常
                finally:
                    client.close()  # 关闭套接字

    def send_message(self, ip_address, message):
        """
        发送消息的方法

        :param ip_address: 发送到那的IP地址
        :param message:  需要发送的消息
        :return: None
        """
        self._is_send = True
        self._ip_address = ip_address
        self._message = message


class MessageThread(Thread):  # 消息线程，从消息队列中取出消息，并打印出来
    def __init__(self, my_queue):
        super().__init__()
        self._queue = my_queue

    def run(self):
        while True:
            if not self._queue.empty():
                print('\n'+self._queue.get())


# noinspection PyTypeChecker,PyGlobalUndefined
def main():
    global order, client_thread, is_start,ip_address,server_thread, address, client
    my_queue = queue.Queue()
    server_thread = ServerThread(my_queue)
    server_thread.setDaemon(True)
    server_thread.start()  # 启动服务器消息接收线程
    client_thread = ClientThread()
    client_thread.setDaemon(True)
    client_thread.start()  # 启动客户端消息发送线程
    message_thread = MessageThread(my_queue)
    message_thread.setDaemon(True)
    message_thread.start()  # 启动消息显示线程
    is_start = True
    ip_address = None
    while True:
        # 操作逻辑控制
        if is_start:
            order = input('请输入需要的服务:\n1.挖矿\n2.交易\n3.下载前面的区块\n4.向对方传输区块信息\n')
            if order == '1':
                CTcoin.mineTransactionPool(get_host_ip())
                client_thread.send_message(ip_address, b'3' + bytes('someone has mined successfully','utf-8'))
            elif order == '2' :
                ip = input('请输入对方地址:')
                money = input('请输入交易金额:')
                port = 1234
                ip_address = ip, port
                is_start = False
            elif order == '3':
                ip = input('请输入其他节点的地址')
                port = 1234
                ip_address = ip, port
                is_start = False
            elif order == '4':
                is_start = False
            else:
                continue
        else:
            message = None
            if ip_address and message != '\r'  and order == '2':
                t1 = transaction(privatekeysender,get_host_ip(), ip, money)
                CTcoin.addtransaction(t1)
                client_thread.send_message(ip_address, b'\x11' +  bytes(str(get_host_ip())+'转账'+ money, 'utf-8'))
                b = json.dumps(t1, default = lambda obj:obj.__dict__, sort_keys = True, indent = 4)
                client_thread.send_message(ip_address, b'2' + bytes(b,'utf-8'))
                message = input('quit()退出当前交易页面\n 转账成功！\n')
                if message == 'quit()':
                    is_start = True
            elif order == '3':
                client_thread.send_message(ip_address, bytes('a', 'utf-8'))
                print('下载成功！')
                message = input('quit()请退出当前页面\n')
                print(CTcoin.chain)
                if message == 'quit()':
                    is_start = True
            elif order == '4':
                #client_thread.send_message(ip_address, b'\x12')
                for index in range(1, len(CTcoin.chain)):
                            pack = json.dumps(CTcoin.chain[index], default = lambda obj:obj.__dict__, sort_keys = True, indent = 4)
                            client_thread.send_message((address[0],1234), b'1' + bytes(pack,'utf-8'))
                print('传输数据中')
                message = input('quit()请退出当前页面\n')
                print(CTcoin.chain)
                if message == 'quit()':
                    is_start = True

                
def get_host_ip():
    """
    查询本机ip地址
    :return: ip
    """
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.10.10.10', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

        
def receive_block(pack):
        transaction_list = []
        pack = eval(pack)
        tx = pack["transaction"]
        for txx in tx:
            transaction1 = transaction(txx['key'],txx['fromAddress'],txx['toAddress'],txx['amount'])
            transaction_list.append(transaction1)
        block1 = Block(pack['timestamp'],transaction_list, pack['previousHash'])
        block1.nonce = pack['nonce']
        CTcoin.chain.append(block1)

def receive_transaction(b):
    def handle(b):
        return transaction(b['key'],b["fromAddress"],b["toAddress"],b["amount"])
    c = json.loads(b, object_hook = handle)
    CTcoin.transactionPool.append(c)


t1 = transaction(privatekeysender, '1', '2', '100')
CTcoin.addtransaction(t1)
CTcoin.mineTransactionPool('1')

if __name__ == '__main__':
    main()

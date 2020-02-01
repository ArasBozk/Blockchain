from Crypto.Hash import SHA3_256
import math
import random

def MerkleTree(leafs):
    for it in range(len(leafs)):
        leafs[it] = SHA3_256.new(leafs[it].encode('utf-8')).digest()
        
    loopC = int(math.log2(len(leafs)))
    for i in range(loopC):
        for t in range (len(leafs)//2):
            leafs[t] = SHA3_256.new(((leafs[2*t] + leafs[2*t+1]))).digest()
            
        leafs = leafs[:len(leafs)//2]

    return leafs[0]

def AddBlock2Chain(PoWLen, TxCnt, block_candidate, PrevBlock):
    Transactions = []
    for b in range(TxCnt):
        Transactions.append("".join(block_candidate[9*b:9*b+9]))
    H_r = MerkleTree(Transactions)
    
    if PrevBlock != "":
        Transactions = []
        for b in range(TxCnt):
            Transactions.append("".join(PrevBlock[9*b:9*b+9]))
        Prev_H_r = MerkleTree(Transactions)
        PrevPow = PrevBlock[-2][len("Previous PoW: "):-1].encode('UTF-8')
        Nonce = int(PrevBlock[-1][7:-1])
        PrevPow = SHA3_256.new( Prev_H_r + PrevPow + Nonce.to_bytes((Nonce.bit_length()+7)//8, byteorder = "big")).hexdigest()
    else:    
        PrevPow =  "00000000000000000000"   # If PrevBlock = "" => it is assumed that Previous PoW is 00000000000000000000

    HoldPrevPow = PrevPow
    PrevPow = PrevPow.encode('UTF-8')

    hash_val_hex = ""
    val = 2**1028-1 #257-1
    while hash_val_hex[:PoWLen] != "0"*PoWLen:
        Nonce = random.randint(0,val)   #Create random Nonce
        hash_val_hex = SHA3_256.new( H_r + PrevPow + Nonce.to_bytes((Nonce.bit_length()+7)//8, byteorder = "big")).hexdigest()

    NewBlock = ''.join(block_candidate[:TxCnt*9])
    NewBlock = NewBlock + "Previous PoW: " + PrevPow.decode('UTF-8')  + '\n' + "Nonce: " + str(Nonce) + '\n'
    return NewBlock , HoldPrevPow
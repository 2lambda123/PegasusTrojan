import struct
import hashlib


_SERIALIZED_CREDS_BUFFER_LEN = 22

def decrypt_envelop(xored):
    dwKey = struct.unpack("<I", xored[:4])[0]
    print "dwKey:  %08x" % dwKey

    data = map(ord, xored[4:])
    for i in range(len(data)):
        #print "%02x^%02x=%02x"%(data[i], dwKey, data[i] ^ (dwKey & 0xFF))
        data[i] ^= (dwKey & 0xFF)
        dwKey = (dwKey >> 5) | (dwKey << (32 - 5));
        dwKey &= 0xFFFFFFFF
    
    decData = ''.join("%c"%x for x in data)
    print "hash: "+decData[:20].encode('hex')
    print "id:   "+decData[20].encode('hex')
    print "Data: "+decData[21:].encode('hex')

    temp = "\0"*20+decData[20:]
    calcedHash = hashlib.sha1(temp).hexdigest()
    print "Calced Hash: "+calcedHash
    if(calcedHash == decData[:20].encode('hex')):
        print "Success"
    else:
        print "Fail"
    return decData[21:]
    
def decrypt_mailslot(xored):
    dwKey = xored[4:8] + xored[:4]
    print "dwKey:   %s" % dwKey.encode('hex')
    data = xored[8:]
    
    dwKey = dwKey * (len(data)/len(dwKey) + 1)
    dwKey = dwKey[:len(data)]
    
    decData = [ord(a) ^ ord(b) for a,b in zip(dwKey,data)]
    if _SERIALIZED_CREDS_BUFFER_LEN + decData[10] + decData[11] + decData[12] + decData[13] == len(xored):
        print "Mailslot decode Good"
    else:
        print "Mailslot decode BAD"
    decData = ''.join("%c"%x for x in decData)
    print decData.encode('hex')
    return decData
    
def decrypt_strings(mailslot):
    def decrypt_packed_string(xored):
        dwKey1 = struct.unpack("<I", xored[:4])[0]
        dwKey2 = struct.unpack("<I", xored[4:8])[0]
        #print "dwKey1:  %08x" % dwKey1
        #print "dwKey2:  %08x" % dwKey2
        
        data = map(ord, xored[8:])
        for i in range(len(data)):
            #print "*pOut = %02x ^ %02x ^ %02x"%(data[i], dwKey1 & 0xFF, dwKey2 & 0xFF)
            data[i] ^= (dwKey1 & 0xFF) ^ (dwKey2 & 0xFF)
            dwKey1 = (dwKey1 >> 3) | (dwKey1 << (32 - 3))
            dwKey2 = (dwKey2 >> 2)
            dwKey1 &= 0xFFFFFFFF
            dwKey2 &= 0xFFFFFFFF
        return ''.join(map(chr, data))
            
    computer_name_len = ord(mailslot[_SERIALIZED_CREDS_BUFFER_LEN - 12 + 0])
    domain_name_len = ord(mailslot[_SERIALIZED_CREDS_BUFFER_LEN - 12 + 1])
    username_len = ord(mailslot[_SERIALIZED_CREDS_BUFFER_LEN - 12 + 2])
    password_len = ord(mailslot[_SERIALIZED_CREDS_BUFFER_LEN - 12 + 3])
    
    index = _SERIALIZED_CREDS_BUFFER_LEN - 8
    computer_name_xored = mailslot[index: index + computer_name_len]
    index += computer_name_len
    domain_name_xored = mailslot[index: index + domain_name_len]
    index += domain_name_len
    username_xored = mailslot[index: index + username_len]
    index += username_len
    password_xored = mailslot[index: index + password_len]
    
    computer_name = decrypt_packed_string(computer_name_xored)
    domain_name = decrypt_packed_string(domain_name_xored)
    username = decrypt_packed_string(username_xored)
    password = decrypt_packed_string(password_xored)
    print "Computer name:\t%s\nDomain:\t\t%s\nUsername:\t%s\nPassword:\t%s" % (computer_name, domain_name, username, password)
    

data = open('cipher.txt', 'rb').read()
data2 = decrypt_envelop(data)
data3 = decrypt_mailslot(data2)
data4 = decrypt_strings(data3)
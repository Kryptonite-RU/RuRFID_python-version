import os, math
import random
from pygost import gost3412, gost3413
from multiprocessing import Process, Pipe


"""
Вспомогательные функции
"""

#случайное число от 0 до p - 1
def rand(p):
    rng = random.SystemRandom()
    rand_x = rng.randint(0, p)
    return rand_x

# Переработка ключа из числа в масив байт, big-endian 
def key_to_byte(key, key_len):
    key_byte = bytearray(key_len)
    i = 0
    while (key > 0):
        key_byte[i] = key & 0xff
        key >>= 8
        i += 1
    return key_byte[::-1]

# Big-endian
def concat(num_and_len, size):
    cnt = 0
    length = 0
    for el in num_and_len:
        num = el[0]  
        cnt ^= (num << length)
        length += el[1]
    byte_cnt = bytearray(size)
    for i in range(size - 1, -1, -1):
        byte_cnt[i] = cnt & 0xff
        cnt >>= 8
    return byte_cnt

def unconcat(byte_cnt, all_lens):
    cnt = 0
    for i in byte_cnt:
        cnt <<= 8
        cnt ^= i
    param = []
    for l in all_lens:
        num = 0
        for i in range(l):
            num ^= (cnt & 1) << i
            cnt >>= 1
        param = [num] + param
    return param

def print_(name : str, x, file, length = 0, mode = 'def'):

    if (mode == 'bin'):
        file.write(name + '0' * (length - len(bin(x)) + 2) +  bin(x)[2:] +  " \n")
        a = x.to_bytes(length // 8 + 1, 'big')
        for el in a:
            file.write(hex(el) +  " ")
        file.write('\n')
    elif  (type(x) == int):
        file.write(name +  " ") 
        a = x.to_bytes(length // 8 , 'big')
        for el in a:
            file.write(hex(el) +  " ")
        file.write('\n')
        
    elif (type(x) == bytearray or type(x) == bytes):
        file.write(name + " ") 
        for el in x:
            file.write(hex(el) +  " ")
    file.write('\n')
    return 

"""
Класс общих, заранее известных для метки и устройства данных
"""

class base:
    def __init__(self):
        self.C_TAM = {
            0 : 0,
            2 : 1, 
            3 : 2
        }
        self.C_IAM = {
            0 : 3,
            2 : 4, 
            3 : 5
        }
        self.C_MAM1 = {
            0 : 6,
            2 : 7, 
            3 : 8
        }
        self.C_MAM2 = {
            0 : 9,
            2 : 10, 
            3 : 11
        }
        self.Key_E = [0x8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef] +  [i for i in range(10000, 1000000, 3000)]
        self.Key_M = [0xffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff] + [i for i in range(10001, 1000000, 3000)]
        self.Key = [0x44556677889900aabbccddeeff1122330123456789abcdeffedbca9876543210] + [i for i in range(10002, 1000000, 3000)]
        self.KeyIds = [z for z in range(len(self.Key))] 
        self.key_len = 32

    def Protect(self, ProtMode, Resp, KeyID, block_size, data_, cyther, file, IV, Profile = 0, BlockCount = 0, mode = 0):
        """Protect function

        :param ProtMode: mode of operation 
        :param bytes Resp: _Resp for TAM\IAM\MAM
        :param int KeyID: identification of the key
        :param int block_size:the size of the block for the cyther, bytes
        :param bytes data_: data in bytes
        :param cyther: the cyther used, class
        :param file: txt file to print result to
        :param IV: Initialization vector, bytearray
        :param Profile: *extra parameter, memory pointer
        :param int Blockcount: *extra parameter, blocks of data to operate on
        :param mode: encryptor - 0, decryptor - 1
    """
        if (ProtMode == 0):
            return Resp

        #ключ для имитовставки - big-endian 
        key = self.Key_M[KeyID]
        key_byte_m = key_to_byte(key, self.key_len)
            
        #Подгoтовка требуемых данных к отправке
        data = bytearray(data_[Profile : Profile + BlockCount * block_size])

        print_('sending data: ', data, file)  
        # с шифрованием данных или без ?
        if (ProtMode & 1 == 0): #Protmode == 10
            print('aaaaa', len(Resp + data))
            for el in Resp + data:
                print(hex(el), end = " ")
            print()
            print('key_m')
            for i in key_byte_m:
                print(hex(i), end = ' ')
            print()
            MAC = gost3413.mac(cyther(key_byte_m).encrypt, block_size, Resp + data)
            print('MAC')
            for el in MAC:
                print(hex(el), end = " ")
            print()
            TAM_response = Resp + bytearray(data[Profile: Profile + 
                BlockCount * block_size]) + MAC
            return TAM_response
                
        else: #Protmode == 11
            #Ключ для CBC
            key = self.Key_E[KeyID]
            key_byte_e = key_to_byte(key, self.key_len)

            print_('IV: ', IV, file)

            if (mode == 0):
                cbc_data = IV + gost3413.cbc_encrypt(cyther(key_byte_e).encrypt, block_size, 
                    data, IV)
            
            
            elif (mode == 1):
                cbc_data = IV + gost3413.cbc_encrypt(cyther(key_byte_e).decrypt, block_size, 
                    data, IV)
            print_('CBC(data):', cbc_data, file)
            MAC = gost3413.mac(cyther(key_byte_m).encrypt, block_size, 
                    Resp + cbc_data)
            print_('MAC():', MAC, file)
            #допущение - функции шифрования возвращают значения в big-endian
            TAM_response = Resp + cbc_data + MAC
            return TAM_response

def tag(r, w,cyther, mode, IV_Challenge):

    class Tag(base):
        def __init__(self, ID, cyther, data : bytearray, mode, IV_Challenge):
            super().__init__()
            self.memory_limit = 1024
            self.id = ID
            self.data = data
            self.cyther = cyther
            self.step = 2 # начальное состояние - бездействие, для режимов MAM, IAM
            if (cyther == 'magma'):
                self.Chanlen = 60
                self.block_size = 8
                self.enc = gost3412.GOST3412Magma
            elif (cyther == 'grasshopper'):
                self.Chanlen = 124
                self.block_size = 16
                self.enc = gost3412.GOST3412Kuznechik
            if (mode == 3):
                self.TChallenge = IV_Challenge[1]
                self.IV = IV_Challenge[0]
            elif (mode == 2):
                self.IV = IV_Challenge[0]
            elif (mode == 1):
                self.TChallenge = IV_Challenge[0]
            else:
                self.TChallenge = rand(2 ** self.Chanlen)
                self.IV = concat([(rand(2 ** (self.block_size * 8)), self.block_size * 8)], self.block_size)
            

        def check_profile_blockcount(self, Profile, BlockCount):
            if (Profile < len(self.data) and Profile + BlockCount * self.block_size <= len(self.data) 
                and BlockCount > 0):
                return 1
            return 0

        def cyther_init(self, KeyID):
            self.KeyID = KeyID
            key = self.Key[KeyID]
            key_byte = key_to_byte(key, self.key_len)
            self.E = self.enc(key_byte)
        
        def TAM_or_MAM1_response(self, AuthMode, mes, mes_len, file):
        
        # параметры MAM1_message: Authmode, Step, ProtMode, PAD, KeyID, IChallenge, *Profile, *BlockCount
        # параметры TAM_message: Authmode, ProtMode, KeyID, IChallenge, *Profile, *BlockCount

            control_byte = bytearray(1)
            if (AuthMode == 2):
                ProtMode = (mes[1] >> 2) & 3
                Step = (mes[1] >> 4) & 3
                length = [ 6, 2, 2, 2]
                ind = 1
                C_AM = self.C_MAM1[ProtMode]
                self.step = 0
                if (Step != 0):
                    file.write('Error, incorrect parameters \n')
                    control_byte[0] = 19
                    return control_byte


            else: #AuthMode = 0
                ProtMode = (0x30 & mes[1]) >> 4
                length = [2, 2]
                ind = 0
                C_AM = self.C_TAM[ProtMode]
        
            # Проверка соответствия наличия доп. параметров с ProtMode и длины
            if (ProtMode == 0 and (mes_len - 1) * 8 == self.Chanlen + 12 + 8 * ind):
                length =  [self.Chanlen, 8] + length
            elif (ProtMode != 0 and (mes_len - 1) * 8 == self.Chanlen + 28 + 8 * ind):
                length = [4, 12, self.Chanlen, 8] + length
            else:
                file.write('Error, incorrect use of extra parameters or length \n')
                control_byte[0] = 21
                return control_byte

            _message = unconcat(mes[1: mes_len], length) 

            #Проверка корректности данных в сообщении
            KeyID = _message[2 + 2 * ind]
            IChallenge = _message[3 + 2 * ind]

            if (ProtMode == 1 or ProtMode > 3 or KeyID not in self.KeyIds):
                file.write('Error, incorrect ProtMode or KeyID \n')
                control_byte[0] = 23
                return control_byte

            if (ProtMode != 0):
                Profile = _message[4 + 2 * ind]
                BlockCount = _message[5 + 2 * ind]

                if (self.check_profile_blockcount(Profile, BlockCount) == 0):
                    file.write('Error, incorrect Profile or BlockCount \n')
                    control_byte[0] = 23
                    return control_byte
                
            #Инициализация шифра с ключем шифрования
            self.cyther_init(KeyID)

            #Формирование параметра T_resp
            enc_data = concat([(IChallenge, self.Chanlen), (C_AM, 4)], self.block_size)
            T_resp = self.E.encrypt(enc_data)
            print_('TResp:', T_resp, file)
            #Формирование TAM_or_MAM1_response
            if (ProtMode != 0):
                TAM_or_MAM1_response = control_byte + self.Protect(ProtMode, T_resp, KeyID, self.block_size,
                    self.data, self.enc, file, self.IV, Profile, BlockCount)
            else:
                TAM_or_MAM1_response = control_byte + self.Protect(ProtMode, T_resp, KeyID, self.block_size,
                    self.data, self.enc, file, self.IV)

            if (AuthMode == 2):
                PAD = 0

                print_('Sec:', TAM_or_MAM1_response[1:], file)
                TChallenge_Pad = concat([(PAD, 4), (self.TChallenge, self.Chanlen)], (self.Chanlen + 4) // 8)
                TAM_or_MAM1_response += TChallenge_Pad

            return TAM_or_MAM1_response

        def IAM_or_MAM2_response(self, AuthMode, mes, mes_len, file):

            # параметры MAM2_message: Authmode, Step, ProtMode, PAD, *Profile, *BlockCount, Sec
            # параметры IAM2_message: Authmode, Step, ProtMode, PAD, *Profile, *BlockCount, Sec
            # параметры IAM1_message: Authmode, Step, PAD, KeyID
            control_byte = bytearray(1)
            Step = (mes[1] >> 4) & 3

            if (Step == 0 and self.step == 2 and AuthMode == 1):
                self.step = 0
                if ((mes_len - 1) * 8 != 16):
                    file.write('Error, incorrect length of IAM1_message \n')
                    control_byte[0] = 27
                    return control_byte

                length = [8, 4, 2, 2]
                IAM_message = unconcat(mes[1: mes_len], length)

                if (IAM_message[3] not in self.KeyIds):
                    file.write('Error, incorrect KeyID \n')
                    control_byte[0] = 29
                    return control_byte

                self.cyther_init(IAM_message[3])
                #Формирование IAM1_response
                PAD = 0
                
                #TChallenge = rand(2 ** self.Chanlen)
                
                print_('TChallenge:', self.TChallenge, file, self.Chanlen, 'bin')

                #self.TChallenge = self.TChallenge

                IAM1_response = control_byte + concat([(PAD, 4), (self.TChallenge, self.Chanlen)], 
                    (self.Chanlen + 4) // 8)
                
                return IAM1_response

            elif (Step == 1 and self.step == 0): 
                AuthMode_recv = (mes[1] >> 6) & 3
                ProtMode = (mes[1] >> 2) & 3
                if (AuthMode_recv != AuthMode):
                    file.write('Error, incorrect AuthMode \n')
                    control_byte[0] = 31
                    return control_byte

                if (AuthMode == 1):   
                    C_AM = self.C_IAM[ProtMode]           

                else:
                    C_AM = self.C_MAM2[ProtMode]

                Profile = 0
                BlockCount = 0
                if (mes_len - 2  - self.block_size != 0):
                    Profile, BlockCount = unconcat(mes[2  : 4 ], [4, 12])
                    if (self.check_profile_blockcount(Profile, BlockCount) == 0):
                        print('Error, incorrect Profile and BlockCount')
                        control_byte[0] = 35
                        return control_byte


                if ((ProtMode == 0 and mes_len != 2 + self.block_size) or
                    (ProtMode == 2 and mes_len != 4  + (2 + BlockCount) * self.block_size) or
                    (ProtMode == 3 and mes_len != 4  + (3 + BlockCount) * self.block_size )):
                    file.write('Error, incorrect use of extra parameters or incorrect length \n')
                    control_byte[0] = 37
                    return control_byte                


                if (ProtMode == 0):
                    I_resp = mes[2 : mes_len]
                   
                    resp = concat([(self.TChallenge, self.Chanlen), (C_AM, 4)], (self.Chanlen + 4) // 8)
                    I_resp_ = self.E.encrypt(resp)

                    I_recv_num = unconcat(I_resp, [len(I_resp)])[0]
                    I_exam_num = unconcat(I_resp_, [len(I_resp_)])[0]
                    if (I_recv_num != I_exam_num):
                        control_byte[0] = 39
                    return control_byte

                elif (ProtMode & 1 ==  0): #ProtMode = 10
                    I_resp = mes[4 : self.block_size + 4 ]
                    data = mes[self.block_size + 4 : 
                        (1 + BlockCount) * self.block_size + 4 ]
                    MAC = mes[(1 + BlockCount) * self.block_size + 4 : mes_len]

                    #Проверка IResp
                    resp = concat([(self.TChallenge, self.Chanlen), (C_AM, 4)], (self.Chanlen + 4) // 8)
                    I_resp_ = self.E.encrypt(resp)

                    I_recv_num = unconcat(I_resp, [len(I_resp)])[0]
                    I_exam_num = unconcat(I_resp_, [len(I_resp_)])[0]
                    if (I_recv_num != I_exam_num):
                        control_byte[0] = 39
                    else:
                        #Проверка имитовставки
                        key = self.Key_M[self.KeyID]
                        key_byte_m = key_to_byte(key, self.key_len)
                        MAC_exam = gost3413.mac(self.enc(key_byte_m).encrypt, self.block_size, I_resp + data)
                        MAC_num = unconcat(MAC, [len(MAC)])[0]
                        MAC_exam_num = unconcat(MAC_exam, [len(MAC_exam)])[0]
                        if (MAC_num != MAC_exam_num):
                            control_byte[0] = 41
                        else:
                            print_('recieved data:', data, file)

                            #Запись данных на метку
                            file.write('old metka data:' +  str(self.data) + '\n')
                            for i in range(BlockCount * self.block_size):
                                self.data[Profile + i] = data[i]
                            file.write('metka data:' + str(self.data) + '\n')
                    return control_byte

                else: # ProtMode = 11
                    I_resp = mes[4 : self.block_size + 4 ]
                    cbc_data = mes[self.block_size + 4 : 
                        (2 + BlockCount) * self.block_size + 4 ]
                    MAC = mes[(2 + BlockCount) * self.block_size + 4 : mes_len]


                    #Проверка IResp
                    resp = concat([(self.TChallenge, self.Chanlen), (C_AM, 4)], (self.Chanlen + 4) // 8)
                    I_resp_ = self.E.encrypt(resp)

                    I_recv_num = unconcat(I_resp, [len(I_resp)])[0]
                    I_exam_num = unconcat(I_resp_, [len(I_resp_)])[0]
                    if (I_recv_num != I_exam_num):
                        control_byte[0] = 39
                    else:
                        #Проверка имитовставки
                        key = self.Key_M[self.KeyID]
                        key_byte_m = key_to_byte(key, self.key_len)
                        MAC_exam = gost3413.mac(self.enc(key_byte_m).encrypt, self.block_size, I_resp + cbc_data)
                        MAC_num = unconcat(MAC, [len(MAC)])[0]
                        MAC_exam_num = unconcat(MAC_exam, [len(MAC_exam)])[0]
                        if (MAC_num != MAC_exam_num):
                            control_byte[0] = 41 
                        else:
                            IV = cbc_data[:self.block_size]
                            
                            #Ключ для CBC
                            key = self.Key_E[self.KeyID]
                            key_byte_e = key_to_byte(key, self.key_len)
                            data = gost3413.cbc_decrypt(self.enc(key_byte_e).encrypt, 
                                self.block_size, cbc_data[self.block_size:], IV)
                            
                            print_('recieved data:', data, file)

                            #Запись данных на метку
                            file.write('old metka data:' + str(self.data) + '\n')
                            for i in range(BlockCount * self.block_size):
                                self.data[Profile + i] = data[i]
                            file.write('new metka data:' +  str(self.data) + '\n')
                    return control_byte
            else:
                file.write('Error, wrong Step \n')
                control_byte[0] = 25
                return control_byte
          

    # Создание начальных параметров метки
    ID = os.getpid() % 100

    #data = bytearray([0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88]) magma
    data = bytearray([0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88, 0x99, 0x99, 0x00, 0x00, 0xAA, 0xAA, 0xBB, 0xBB, 0xCC, 0xCC, 0xDD, 0xDD, 0xEE, 0xEE, 0xFF, 0xFF])

    resp_tag = Tag(ID, cyther, data, mode, IV_Challenge)
    #Передача устройству ID
    w.send(ID)

    #Получение сообщения
    mes = bytearray(261) # максимальная длина сообщения среди всех режимов
    mes_len = r.recv_bytes_into(mes)

    #Недоступный ID метки 
    if (mes[0] != 0):
        r.close()
        w.close()
        return 

    #Определение режима - проверка AuthMode, получение ProtMode
    AuthMode = (0xc0 & mes[1]) >> 6
    
    if (AuthMode == 0): #режим TAM
        file = open('TAM_tag.log', 'a+')
        TAM_response = resp_tag.TAM_or_MAM1_response(AuthMode, mes, mes_len, file)
       
        print_('TAM_response:', TAM_response[1:], file)

        # Отправка TAM_response
        w.send_bytes(TAM_response)
        r.close()
        w.close()
        file.write('\n ___ END_TEST_TAG_______ \n')
        file.close()
        return   

    elif (AuthMode == 1): # режим IAM
        file = open('IAM_tag.log', 'a+')
        IAM1_response = resp_tag.IAM_or_MAM2_response(AuthMode, mes, mes_len, file)

        # Отправка IAM1_response
        print_('IAM1_response:', IAM1_response[1:], file)
        w.send_bytes(IAM1_response)
        if (IAM1_response[0] != 0):
            w.close()
            r.close()
            return 

        #Получение IAM2_message
        IAM_mes = bytearray(25 + 2 * resp_tag.block_size + resp_tag.memory_limit) 
        IAM_mes_len = r.recv_bytes_into(IAM_mes)
        if (IAM_mes[0] != 0):
            r.close()
            w.close()
            return 
        
        final_ans = resp_tag.IAM_or_MAM2_response(AuthMode, IAM_mes, IAM_mes_len, file)
        w.send_bytes(final_ans)
        r.close()
        w.close()
        file.write('\n ___END_TEST_IAM______\n')
        file.close()
        return 

    elif (AuthMode == 2): # режим MAM
        file = open('MAM_tag.log', 'a+')

        MAM1_response = resp_tag.TAM_or_MAM1_response(AuthMode, mes, mes_len, file)
        print_('MAM1_response:', MAM1_response[1:], file)
        w.send_bytes(MAM1_response)
        
        if (MAM1_response[0] != 0):
            r.close()
            w.close()
            return
        
        #Получение MAM2_message
        MAM2_mes = bytearray(25 + 2 * resp_tag.block_size + resp_tag.memory_limit) 
        MAM2_mes_len = r.recv_bytes_into(MAM2_mes)

        if (MAM2_mes[0] != 0):
            r.close()
            w.close()
            return 
        
        final_ans = resp_tag.IAM_or_MAM2_response(AuthMode, MAM2_mes, MAM2_mes_len, file)
        w.send_bytes(final_ans)
        r.close()
        w.close()
        file.write('\n______END_TAST_MAM______\n')
        file.close()
        return 
    
    else: #AuthMode > 2 or AuthMode < 0
        control_byte = bytearray(1)
        control_byte[0] = 43
        L.acquare()
        print('Error, inorrect AuthMode \n')
        L.release()
        w.send_bytes(control_byte)
        w.close()
        r.close()
        return    

    

def communication(cyther, interrogator_parameters, file, data = bytearray(1), mode_int = 0, mode_tag = 0, IV_Challenge_int = [], 
    IV_Challenge_tag = []):


    control_byte = bytearray(1)
    control_byte[0] = 0

    #Устройство
    class Interrogator(base):
        def __init__(self, param, cyther, data, mode, IV_Challenge):
            super().__init__()
            self.Authmode = param['AuthMode'] 
            self.ids = param['ids']
            self.data = data
            self.ProtMode = param['ProtMode'][0]
            if (cyther == 'magma'):
                self.Chanlen = 60
                self.block_size = 8
                self.enc = gost3412.GOST3412Magma
            elif (cyther == 'grasshopper'):
                self.Chanlen = 124
                self.block_size = 16
                self.enc = gost3412.GOST3412Kuznechik
            if (mode == 3):
                self.IChallenge = IV_Challenge[1]
                self.IV = IV_Challenge[0]
            elif (mode == 2):
                self.IV = IV_Challenge[0]
            elif (mode == 1):
                self.IChallenge = IV_Challenge[0]
            else:
                self.IChallenge = rand(2 ** self.Chanlen)
                self.IV = concat([(rand(2 ** (self.block_size * 8)), self.block_size * 8)], self.block_size)
            

        def cyther_init(self, KeyID):
            if (KeyID in self.KeyIds):
                # ключ в big-endian
                key = self.Key[KeyID]
                self.KeyID = KeyID
                key_byte = key_to_byte(key, self.key_len)
                self.E = self.enc(key_byte)
                return 0
            else:
                return 1

        #проверка id
        def check_id(self, id):
            for ident in self.ids:
                if (ident == id):
                    return 1
            return 0

        def construct_TAM_mess(self, extra_param, extra_size = 0):

            size = (12 + self.Chanlen + extra_size) // 8
            param_and_len = extra_param 
            param_and_len += [(self.IChallenge, self.Chanlen), 
            (self.KeyID, 8), (self.ProtMode, 2), (self.Authmode, 2)]
            return self.IChallenge, concat(param_and_len, size)

        def construct_IAM2_message(self, TChallenge, file, Profile = 0, Blockcount = 0):
            Step = 1
            PAD = 0
            
            C_IAM = self.C_IAM[self.ProtMode]
            tmp = concat([(TChallenge, self.Chanlen), (C_IAM, 4)], (self.Chanlen + 4) // 8)
            I_Resp = self.E.encrypt(tmp)
            print_('IResp:', I_Resp, file)

            
            Sec = self.Protect(self.ProtMode, I_Resp, self.KeyID, self.block_size,
                self.data, self.enc, file, self.IV, Profile, Blockcount, 1)
            print_('Sec:', Sec, file)

            if (self.ProtMode != 0):
                param = [(Blockcount, 4), (Profile, 12), 
                    (PAD, 2), (self.ProtMode, 2), (Step, 2), (self.Authmode, 2)]
                param_size = 24 
            else:
                param = [(PAD, 2), (self.ProtMode, 2), (Step, 2), (self.Authmode, 2)]
                param_size = 8 
            IAM2_message = concat(param, param_size // 8) + Sec
            return IAM2_message

        def construct_MAM_message(self, Step, param, extra_param, size, file, TChallenge = 0, Profile = 0, Blockcount = 0):
            byte_ = bytearray(1)
            if (Step == 0):
                size_ = (size + 16 * (len(extra_param) != 0)) // 8

                #IChallenge = rand(2 ** self.Chanlen)

                print_('IChallenge:', self.IChallenge, file, self.Chanlen, 'bin')
                MAM_message = byte_ + concat(extra_param + [(self.IChallenge, self.Chanlen)] + param, size_)
                IChallenge = self.IChallenge

            elif (Step == 1):
                IChallenge = 0
                size_ = (size + 16 * (len(extra_param) != 0)) // 8
                tmp = concat(extra_param + param, size_) 

                C_MAM = self.C_MAM2[self.ProtMode]

                tmp_2 = concat([(TChallenge, self.Chanlen), (C_MAM, 4)], (self.Chanlen + 4) // 8)

                I_Resp = self.E.encrypt(tmp_2)

                print_('IResp:', I_Resp, file)
                Sec = self.Protect(self.ProtMode, I_Resp, self.KeyID, self.block_size,
                    self.data, self.enc, file, self.IV, Profile, Blockcount, 1)

                print_('Sec:', Sec, file)
                MAM_message = byte_ + tmp + Sec
            else:
                byte_[0] = 15
                MAM_message = byte_
            return IChallenge, MAM_message

        def check_TAM_or_MAM1_response(self, _response, _response_len, IChallenge, AuthMode, file, Blockcount = 0):

            if (AuthMode == 0):
                C_AM_ = self.C_TAM[self.ProtMode]
            else:
                C_AM_ = self.C_MAM1[self.ProtMode]
            #Проверка данных в TAM_response
            if (self.ProtMode == 0):
                T_resp = _response[1:]
                T_resp_decode = self.E.decrypt(T_resp)
                C_AM, IChallenge_rec = unconcat(T_resp_decode, [self.Chanlen, 4])
                
                if (C_AM == C_AM_ and IChallenge_rec == IChallenge):
                    return 0
                else:
                    return 5

            elif (self.ProtMode & 1 ==  0): #ProtMode = 10
                T_resp = _response[1: self.block_size + 1]
                data = _response[self.block_size + 1: 
                    (1 + Blockcount) * self.block_size + 1]
                MAC = _response[(1 + Blockcount) * self.block_size + 1 : _response_len]
                
                #Проверка данных в TAM_response - C_TAM
                T_resp_decode = self.E.decrypt(T_resp)
                C_AM, IChallenge_rec = unconcat(T_resp_decode, [self.Chanlen, 4])
                if (C_AM != C_AM_ or IChallenge_rec != IChallenge):
                    return 5
                else:
                    #Проверка имитовставки
                    key = self.Key_M[self.KeyID]
                    key_byte_m = key_to_byte(key, self.key_len)
                    MAC_exam = gost3413.mac(self.enc(key_byte_m).encrypt, self.block_size, T_resp + data)
                    MAC_num = unconcat(MAC, [len(MAC)])[0]
                    MAC_exam_num = unconcat(MAC_exam, [len(MAC_exam)])[0]
                    if (MAC_num != MAC_exam_num):
                        return 7
                    else:
                        print_('recieved data : ', data, file)  
                        return 0

            else: # ProtMode = 11
                T_resp = _response[1: self.block_size + 1]
                cbc_data = _response[self.block_size + 1: 
                    (2 + Blockcount) * self.block_size + 1]
                MAC = _response[(2 + Blockcount) * self.block_size + 1 : _response_len]
                #Проверка данных в TAM_response - C_TAM
                T_resp_decode = self.E.decrypt(T_resp)
                C_TAM, IChallenge_rec = unconcat(T_resp_decode, [self.Chanlen, 4])
                if (C_TAM != C_AM_ or IChallenge_rec != IChallenge):
                    return 5
                else:
                    #Проверка имитовставки
                    key = self.Key_M[self.KeyID]
                    key_byte_m = key_to_byte(key, self.key_len)
                    MAC_exam = gost3413.mac(self.enc(key_byte_m).encrypt, self.block_size, T_resp + cbc_data)

                    MAC_num = unconcat(MAC, [len(MAC)])[0]
                    MAC_exam_num = unconcat(MAC_exam, [len(MAC_exam)])[0]
                    
                    if (MAC_num != MAC_exam_num):
                        return 7
                    else:
                        IV = cbc_data[:self.block_size]  
                        #Ключ для CBC
                        key = self.Key_E[self.KeyID]
                        key_byte_e = key_to_byte(key, self.key_len)
                        data = gost3413.cbc_decrypt(self.enc(key_byte_e).decrypt, self.block_size, cbc_data[self.block_size:], IV)
                        
                        print_('recieved data:', data, file)
                        return 0 

            
    #Инициализация устройства
    interrogator = Interrogator(interrogator_parameters, cyther, data, mode_int, IV_Challenge_int)
    print_('AuthMode:', interrogator.Authmode, file, 8)
    print_('ProtMode:', interrogator.ProtMode, file, 8)

    if (interrogator.cyther_init(interrogator_parameters['KeyID'])):
        file.write('Error, no such KeyID found \n')
        return 2

    print_('K_KeyID:', interrogator.Key[interrogator.KeyID], file,  interrogator.key_len * 8)
    print_('K_e_KeyID:', interrogator.Key_E[interrogator.KeyID], file, interrogator.key_len * 8)
    print_('K_m_KeyID:', interrogator.Key_M[interrogator.KeyID], file, interrogator.key_len * 8)


    #Создание процесса - метки
    r, w_child = Pipe(duplex = False)
    r_child, w = Pipe(duplex = False)
    p = Process(target=tag, args=(r_child, w_child, cyther, mode_tag, IV_Challenge_tag))
    p.start()
    r_child.close()
    w_child.close()

    #Получение ID
    resp_ID = r.recv()

    #Проверка ID
    if (interrogator.check_id(resp_ID) == 0):
        file.write('Error, no such ID found \n')
        control_byte[0] = 1
        w.send_bytes(control_byte)
        p.join()
        w.close()
        r.close()
        return 1 

    #Режим общения
    if (interrogator.Authmode == 0): #TAM

        # Подготовка всех параметров к отправке на метку
        extra_param = []
        extra_size = 0
        Blockcount = 0
        if ('Profile_Blockcount' in interrogator_parameters.keys()):
            extra_param = [(interrogator_parameters["Profile_Blockcount"][0], 16)]
            extra_size = 16
            Blockcount = extra_param[0][0] & 0xf
            Profile = extra_param[0][0] >> 4
            print_('Profile:', Profile, file, 16)
            print_('Blockcount:', Blockcount, file, 8)
        TAM_message = control_byte 
        IChallenge, part_message = interrogator.construct_TAM_mess(extra_param, extra_size)
        TAM_message += part_message

        #Отправка TAM_message
        print_('IChallenge:', IChallenge, file, interrogator.Chanlen, 'bin')
        print_('TAM_message:', TAM_message[1:], file)
        
        w.send_bytes(TAM_message)

        #Получение TAM_response
        TAM_response = bytearray(1 + interrogator.block_size + 
        interrogator.block_size * (2 + Blockcount) * (Blockcount != 0))

        TAM_response_len = r.recv_bytes_into(TAM_response)
        w.close()
        r.close()

        # Проверка на корректность данных TAM_Message: результат от процесса метки
        if (TAM_response[0] != 0):
            w.close()
            r.close()
            p.join()
            return int(TAM_response[0])

        #Проверка длинны в TAM_response
        if (interrogator.ProtMode != 3 and TAM_response_len != 1 + interrogator.block_size + 
            interrogator.block_size * (1 + Blockcount) * (Blockcount != 0) or
            interrogator.ProtMode == 3 and TAM_response_len != 1 + interrogator.block_size + 
            interrogator.block_size * (2 + Blockcount) * (Blockcount != 0)): 
            file.write('Error, inaccurate TAM_response length \n')
            p.join()
            return 3
        if (Blockcount != 0):
            return interrogator.check_TAM_or_MAM1_response(TAM_response, TAM_response_len, IChallenge, interrogator.Authmode, file, Blockcount)
        return interrogator.check_TAM_or_MAM1_response(TAM_response, TAM_response_len, IChallenge, interrogator.Authmode, file)

    elif (interrogator.Authmode == 1): #IAM
        PAD = 0
        Step = 0
        # Подготовка всех параметров к отправке на метку
        param = [(interrogator.KeyID, 8), (PAD, 4), (Step, 2), (interrogator.Authmode, 2)]
        IAM1_message = control_byte + concat(param, 2)

        print_('IAM1_message:', IAM1_message[1:], file)
        #Отправка IAM1_message
        w.send_bytes(IAM1_message)

        #Получение IAM1_response
        IAM1_response = bytearray((interrogator.Chanlen + 4) // 8 + 1)
        IAM1_response_len = r.recv_bytes_into(IAM1_response)

        if (IAM1_response_len != (interrogator.Chanlen + 4) // 8 + 1):
            file.write('Error, incorrect IAM1_response length \n')
            control_byte[0] = 9
            w.send_bytes(control_byte)
            p.join()
            w.close()
            r.close()
            return int(control_byte[0])

        TChallenge, _ = unconcat(IAM1_response, [4, interrogator.Chanlen])
        if ('Profile_Blockcount' in interrogator_parameters.keys()):
            Blockcount = interrogator_parameters['Profile_Blockcount'][0] & 0xf
            Profile = interrogator_parameters['Profile_Blockcount'][0] >> 4
            print_('Profile:', Profile, file, 16)
            print_('Blockcount:', Blockcount, file, 8)
            IAM2_message = control_byte + interrogator.construct_IAM2_message(TChallenge, file, Profile, Blockcount)
        else:
            IAM2_message = control_byte + interrogator.construct_IAM2_message(TChallenge, file)
        
        #Отправление IAM2_message
        print_('IAM2_message:', IAM2_message[1:], file)
        w.send_bytes(IAM2_message)
    
        #Получение IAM2_response
        r.recv_bytes_into(control_byte)
        r.close()
        w.close()
        return int(control_byte[0])

    elif (interrogator.Authmode == 2): # MAM

        # MAM1_message
        extra_param = []
        Blockcount = 0
        if ('Profile_Blockcount' in interrogator_parameters.keys() and math.isnan(interrogator_parameters["Profile_Blockcount"][0]) != True):
            extra_param = [(interrogator_parameters["Profile_Blockcount"][0], 16)]
            Blockcount = extra_param[0][0] & 0xf
            Profile = extra_param[0][0] >> 4
            print_('Profile_1:', Profile, file, 16)
            print_('Blockcount_1:', Blockcount, file, 8)
        size = 20 + interrogator.Chanlen
        PAD = 0
        Step = 0
        param = [(interrogator.KeyID, 8), (PAD, 6), (interrogator.ProtMode, 2), 
            (Step, 2),(interrogator.Authmode, 2)]
        IChallenge, MAM1_message = interrogator.construct_MAM_message(Step, param, extra_param, size, file)
    
        #Отправка MAM1_message
        print_('MAM1_message:', MAM1_message[1:], file)
        w.send_bytes(MAM1_message)

        #Получение MAM1_response
        MAM1_response = bytearray(1 + (interrogator.Chanlen + 4) // 8 +interrogator.block_size * (Blockcount + 1 + 2 * (Blockcount != 0)))
        MAM1_response_len = r.recv_bytes_into(MAM1_response)
        if (MAM1_response[0] != 0):
            r.close()
            w.close()
            return int(MAM1_response[0])

        if ((MAM1_response_len != 1 + (interrogator.Chanlen + 4) // 8 + interrogator.block_size and interrogator.ProtMode == 0) or
            (MAM1_response_len != 1 + (interrogator.Chanlen + 4) // 8 + interrogator.block_size * (Blockcount + 2) 
            and interrogator.ProtMode == 2) or (MAM1_response_len != 1 + (interrogator.Chanlen + 4) // 8 + 
            interrogator.block_size * (Blockcount + 3) and interrogator.ProtMode == 3)):
                control_byte[0] = 11
                file.write('Error, incorrect length of MAM1_response \n')
                w.send_bytes(control_byte)
                w.close()
                r.close()
                return int(control_byte[0])
        
        #Обработка сообщения MAM1_response
        sec_len = MAM1_response_len - (interrogator.Chanlen + 4) // 8
        res = interrogator.check_TAM_or_MAM1_response(MAM1_response[: sec_len], sec_len, IChallenge, interrogator.Authmode, file, Blockcount)

        # Результат получения данных с метки - если результат неправильный, перессылка все равно продолжается
        if (res != 0):
            control_byte[0] = res
            file.write('Error, incorrect MAM1_response \n')
            file.write('________END part 1:'+ str(int(control_byte[0])) +  '______________\n')
        else:
            file.write('________END part 1:' +  str(0) +  '______________\n')

        #MAM2_message
        TChallenge, _ = unconcat(MAM1_response[sec_len : MAM1_response_len], [4, interrogator.Chanlen])
        

        # Замена параметров
        interrogator.ProtMode = interrogator_parameters['ProtMode'][1]
 
        print_('ProtMode_2:', interrogator.ProtMode, file, 8)

        extra_param = []
        size = 8 
        PAD = 0
        Step = 1
        
        param = [ (PAD, 2), (interrogator.ProtMode, 2), 
            (Step, 2),(interrogator.Authmode, 2)]



        if ('Profile_Blockcount' in interrogator_parameters.keys() and math.isnan(interrogator_parameters["Profile_Blockcount"][1]) != True):   
            extra_param = [(interrogator_parameters["Profile_Blockcount"][1], 16)]
            Blockcount = extra_param[0][0] & 0xf
            Profile = extra_param[0][0] >> 4
            print_('Profile_2:', Profile, file, 16)
            print_('Blockcount_2:', Blockcount, file, 8)
            _, MAM2_message = interrogator.construct_MAM_message(Step, param, extra_param, size, file, TChallenge, Profile,  Blockcount)
        else:
            _, MAM2_message = interrogator.construct_MAM_message(Step, param, extra_param, size, file, TChallenge)

        #Отправка MAM2_message
        print_('MAM2_message:', MAM2_message[1:], file)
        w.send_bytes(MAM2_message)

        #Получение MAM2_response
        r.recv_bytes_into(control_byte)
        r.close()
        w.close()
        return int(control_byte[0])
        
    else:
        file.write('Error, incorrect AuthMode \n')
        control_byte[0] = 4
        w.send_bytes(control_byte)
        p.join()
        w.close()
        r.close()
        return 111 




def CONTROL_TEST_IAM_magma():


    inter_data = 0x99998888777766661111222233334444 
    IChallenge = 0x0aabcdeffedcbaa0
    TCHallenge = 0x0234567887654321
    tag_IV = bytearray([0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21])
    inter_IV = bytearray([0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76])

    f = open('IAM_int.log', 'w+')
    f.write('__________TESTING IAM__________ \n')
    cyther = 'magma'
    
    
    test_parameters_0 = {
        'AuthMode' : 1,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [0],
        'KeyID' : 0, #задаем без знания ID метки
    }
    test_parameters_2 = {
        'AuthMode' : 1,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [2],
        'KeyID' : 0, #задаем без знания ID метки
        'Profile_Blockcount' : [2]
    }
    test_parameters_3 = {
        'AuthMode' : 1,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [3],
        'KeyID' : 0, #задаем без знания ID метки
        'Profile_Blockcount' : [2]
    }


    inter_data = bytearray([0x99, 0x99, 0x88, 0x88, 0x77, 0x77, 0x66, 0x66,	0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44 ])
    f.write('__________TEST 0__________ \n')
    f.write('__________End ProtMode 0:' + str(communication(cyther, test_parameters_0, f,  inter_data, 0, 1, [], [TCHallenge])) + '__________ \n') 
    
    f.write('__________TEST 2__________ \n')
    f.write('__________End ProtMode 2:' +  str(communication(cyther, test_parameters_2, f, inter_data, 2, 1, 
        [inter_IV], [TCHallenge])) + '__________ \n')
    
    f.write('__________TEST 3__________ \n')
    f.write('__________End ProtMode 3:' +  str(communication(cyther, test_parameters_3, f,  inter_data, 2, 1, 
        [inter_IV], [TCHallenge])) + '__________\n')
    f.close()

    return

def CONTROL_TEST_TAM_magma():

    inter_data = 0x99998888777766661111222233334444 
    IChallenge = 0x0aabcdeffedcbaa0
    TCHallenge = 0x0234567887654321
    tag_IV = bytearray([0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21])
    inter_IV = bytearray([0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76])

    f = open('TAM_int.log', 'w+')
    f.write('__________TESTING TAM__________ \n')
    cyther = 'magma'
    test_parameters_0 = {
        'AuthMode' : 0,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [0],
        'KeyID' : 0, #задаем без знания ID метки
    }
    test_parameters_2 = {
        'AuthMode' : 0,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [2],
        'KeyID' : 0, #задаем без знания ID метки
        'Profile_Blockcount' : [2]
    }
    test_parameters_3 = {
        'AuthMode' : 0,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [3],
        'KeyID' : 0, #задаем без знания ID метки
        'Profile_Blockcount' : [2]
    }


    inter_data = bytearray([0x99, 0x99, 0x88, 0x88, 0x77, 0x77, 0x66, 0x66,	0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44 ])
    f.write('__________TEST 0__________ \n')
    f.write('__________End ProtMode 0:' + str(communication(cyther, test_parameters_0, f,  inter_data, 1, 0, [IChallenge])) + '__________ \n') 
    
    f.write('__________TEST 2__________ \n')
    f.write('__________End ProtMode 2:' +  str(communication(cyther, test_parameters_2, f, inter_data, 1, 2, 
        [IChallenge], [tag_IV])) + '__________ \n')
    
    f.write('__________TEST 3__________ \n')
    f.write('__________End ProtMode 3:' +  str(communication(cyther, test_parameters_3, f,  inter_data, 1, 2, 
        [IChallenge], [tag_IV])) + '__________\n')
    f.close()
    return

def CONTROL_TEST_MAM_magma():
    inter_data = 0x99998888777766661111222233334444 
    IChallenge = 0x0aabcdeffedcbaa0
    TCHallenge = 0x0234567887654321 
    tag_IV = bytearray([0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21])
    inter_IV = bytearray([0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76])
    cyher = 'magma'
    f = open('MAM_int.log', 'w+')
    f.write('__________TESTING TAM__________ \n')
    cyther = 'magma'
    test_parameters_0 = {
        'AuthMode' : 2,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [0, 0],
        'KeyID' : 0, #задаем без знания ID метки
    }
    test_parameters_2 = {
        'AuthMode' : 2,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [2, 2],
        'KeyID' : 0, #задаем без знания ID метки
        'Profile_Blockcount' : [2, 2]
    }
    test_parameters_3 = {
        'AuthMode' : 2,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [3, 3],
        'KeyID' : 0, #задаем без знания ID метки
        'Profile_Blockcount' : [2, 2]
    }
    inter_data = bytearray([0x99, 0x99, 0x88, 0x88, 0x77, 0x77, 0x66, 0x66,	0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44 ])

    f.write('__________TEST 0__________ \n')
    f.write('_______End TEST 0 part 2:' +  str(communication(cyther, test_parameters_0, f, inter_data, 3, 3, 
        [inter_IV, IChallenge], [tag_IV, TCHallenge])) + '_______ \n')

    f.write('__________TEST 2__________ \n')
    f.write('_______End TEST 2 part 2:' + str(communication(cyther, test_parameters_2, f,  inter_data, 3, 3, 
        [inter_IV, IChallenge], [tag_IV, TCHallenge])) + '_______ \n')
  
    f.write('__________TEST 3__________ \n')
    f.write('_______End TEST 3 part 2:'+ str(communication(cyther, test_parameters_3, f,  inter_data, 3, 3, 
        [inter_IV, IChallenge], [tag_IV, TCHallenge])) + '_______ \n')
    f.close()
    return 

def CONTROL_TEST_IAM():


    IChallenge = 0x0aabcdeffedcbaa01223456776543221
    TCHallenge = 0x023456788765432119abcdeffedcba90
    tag_IV = bytearray([0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21])
    inter_IV = bytearray([0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76])
    cyther = 'grasshopper'
    f = open('IAM_int.log', 'w+')
    f.write('__________TESTING IAM__________ \n')
    
    
    
    test_parameters_0 = {
        'AuthMode' : 1,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [0],
        'KeyID' : 0, #задаем без знания ID метки
    }
    test_parameters_2 = {
        'AuthMode' : 1,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [2],
        'KeyID' : 0, #задаем без знания ID метки
        'Profile_Blockcount' : [2]
    }
    test_parameters_3 = {
        'AuthMode' : 1,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [3],
        'KeyID' : 0, #задаем без знания ID метки
        'Profile_Blockcount' : [2]
    }


    inter_data = bytearray([0x99, 0x99, 0x88, 0x88, 0x77, 0x77, 0x66, 0x66,	0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0xFF, 0xFF, 0xEE, 0xEE, 0xDD, 0xDD, 0xCC, 0xCC, 0xAA, 0xAA, 0xBB, 0xBB, 0x00, 0x00, 0x55, 0x55])
    f.write('__________TEST 0__________ \n')
    f.write('__________End ProtMode 0:' + str(communication(cyther, test_parameters_0, f,  inter_data, 0, 1, [], [TCHallenge])) + '__________ \n') 
    
    f.write('__________TEST 2__________ \n')
    f.write('__________End ProtMode 2:' +  str(communication(cyther, test_parameters_2, f, inter_data, 2, 1, 
        [inter_IV], [TCHallenge])) + '__________ \n')
    
    f.write('__________TEST 3__________ \n')
    f.write('__________End ProtMode 3:' +  str(communication(cyther, test_parameters_3, f,  inter_data, 2, 1, 
        [inter_IV], [TCHallenge])) + '__________\n')
    f.close()

    return

def CONTROL_TEST_TAM():

    inter_data = 0x99998888777766661111222233334444FFFFEEEEDDDDCCCCAAAABBBB00005555
    IChallenge = 0x0aabcdeffedcbaa01223456776543221
    TCHallenge = 0x023456788765432119abcdeffedcba90
    tag_IV = bytearray([0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21])
    inter_IV = bytearray([0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76])
    cyther = 'grasshopper'
    f = open('TAM_int.log', 'w+')
    f.write('__________TESTING TAM__________ \n')
    
    test_parameters_0 = {
        'AuthMode' : 0,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [0],
        'KeyID' : 0, #задаем без знания ID метки
    }
    test_parameters_2 = {
        'AuthMode' : 0,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [2],
        'KeyID' : 0, #задаем без знания ID метки
        'Profile_Blockcount' : [2]
    }
    test_parameters_3 = {
        'AuthMode' : 0,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [3],
        'KeyID' : 0, #задаем без знания ID метки
        'Profile_Blockcount' : [2]
    }


    inter_data = bytearray([0x99, 0x99, 0x88, 0x88, 0x77, 0x77, 0x66, 0x66,	0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0xFF, 0xFF, 0xEE, 0xEE, 0xDD, 0xDD, 0xCC, 0xCC, 0xAA, 0xAA, 0xBB, 0xBB, 0x00, 0x00, 0x55, 0x55])
    f.write('__________TEST 0__________ \n')
    f.write('__________End ProtMode 0:' + str(communication(cyther, test_parameters_0, f,  inter_data, 1, 0, [IChallenge])) + '__________ \n') 
    
    f.write('__________TEST 2__________ \n')
    f.write('__________End ProtMode 2:' +  str(communication(cyther, test_parameters_2, f, inter_data, 1, 2, 
        [IChallenge], [tag_IV])) + '__________ \n')
    
    f.write('__________TEST 3__________ \n')
    f.write('__________End ProtMode 3:' +  str(communication(cyther, test_parameters_3, f,  inter_data, 1, 2, 
        [IChallenge], [tag_IV])) + '__________\n')
    f.close()
    return

def CONTROL_TEST_MAM():
    inter_data = 0x99998888777766661111222233334444FFFFEEEEDDDDCCCCAAAABBBB00005555
    IChallenge = 0x0aabcdeffedcbaa01223456776543221
    TCHallenge = 0x023456788765432119abcdeffedcba90
    tag_IV = bytearray([0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21])
    inter_IV = bytearray([0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76])
    cyther = 'grasshopper'
    f = open('MAM_int.log', 'w+')
    f.write('__________TESTING TAM__________ \n')
    test_parameters_0 = {
        'AuthMode' : 2,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [0, 0],
        'KeyID' : 0, #задаем без знания ID метки
    }
    test_parameters_2 = {
        'AuthMode' : 2,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [2, 2],
        'KeyID' : 0, #задаем без знания ID метки
        'Profile_Blockcount' : [2, 2]
    }
    test_parameters_3 = {
        'AuthMode' : 2,
        'ids' : [x for x in range(0, 99)],
        'ProtMode' : [3, 3],
        'KeyID' : 0, #задаем без знания ID метки
        'Profile_Blockcount' : [2, 2]
    }
    inter_data = bytearray([0x99, 0x99, 0x88, 0x88, 0x77, 0x77, 0x66, 0x66,	0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0xFF, 0xFF, 0xEE, 0xEE, 0xDD, 0xDD, 0xCC, 0xCC, 0xAA, 0xAA, 0xBB, 0xBB, 0x00, 0x00, 0x55, 0x55])

    f.write('__________TEST 0__________ \n')
    f.write('_______End TEST 0 part 2:' +  str(communication(cyther, test_parameters_0, f, inter_data, 3, 3, 
        [inter_IV, IChallenge], [tag_IV, TCHallenge])) + '_______ \n')

    f.write('__________TEST 2__________ \n')
    f.write('_______End TEST 2 part 2:' + str(communication(cyther, test_parameters_2, f,  inter_data, 3, 3, 
        [inter_IV, IChallenge], [tag_IV, TCHallenge])) + '_______ \n')
  
    f.write('__________TEST 3__________ \n')
    f.write('_______End TEST 3 part 2:'+ str(communication(cyther, test_parameters_3, f,  inter_data, 3, 3, 
        [inter_IV, IChallenge], [tag_IV, TCHallenge])) + '_______ \n')
    f.close()
    return 


def main():

    CONTROL_TEST_TAM()
    CONTROL_TEST_IAM()
    CONTROL_TEST_MAM()
if __name__ == '__main__':
    main()




"""
Режим работы метки: mode

0 - нслучайные значения
1 - определить значения TChallenge / IChallenge заданными
2 - определить значения IV заданными
3 - определить значения TChallenge / IChallenge, IV заданными

"""

"""
коды ошибок:
1 - неверный ID 
3 - некорректная длина TAM_response
5 - несовпадение параметра TResp в TAM_response или MAM1_response
7 - несовпадение имитовставки в TAM_response или MAM1_response
9 - некорректная длина IAM1_response
11 - некорректная длина MAM1_response
15 - неправильный параметр при конструировании Step MAM2_message
19 - в MAM1_message метка достает Step != 0
21 - несоотвествие ProtMode и наличия Pofile, BlockCount в TAM_message или MAM1_message
23 - недопустимые ProtMode, KeyID, Pofile или BlockCount в TAM_message или MAM1_message
25 - в MAM2_message, IAM1 или IAM2_message метка достает Step != 0 или 1
27 - некорректная длина IAM1_message
29 - недопустимый KeyID в IAM1_message
31 - Несовпадение AuthMode в IAM1_message и IAM2_message или MAM1_message и MAM2_message
33 - несовпадение KeyID в MAM1_message и MAM2_message
35 - недопустимые Pofile или BlockCount в IAM2_message или MAM2_message
37 - несоотвествие ProtMode и наличия Pofile, BlockCount в IAM2_message или MAM2_message
39 - несовпадение параметра IResp в IAM2_message или MAM2_message
41 - несовпадение имитовставки в IAM2_message или MAM2_message
43 - на метку пришло первое сообщение с недопустимым AuthMode
Ошибки в силу реализации:
2 - на устройстве задан неправильный KeyID
4 - на устройстве задан неправильный AuthMode
"""

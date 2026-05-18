class ShiftCipher:
    def __init__(self,key:int):
        self.key = key % 26

    def _to_int(self, char:str) -> int:
        return ord(char.upper()) - ord('A')
    
    def _to_char(self,x:int) -> str:
        return chr(x + ord('A'))
    
    def encrypt(self,plaintext:str) -> str:
        #加密函数
        result = []
        for char in plaintext:
            if char.isalpha():      #isalpha函数用来判断是不是字母
                x = self._to_int(char)
                y = (x + self.key) % 26
                result.append(self._to_char(y))
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self,ciphertext:str) -> str:
        #解密函数
        result = []
        for char in ciphertext:
            if char.isalpha():      #isalpha函数用来判断是不是字母
                y = self._to_int(char)
                x = (y - self.key) % 26
                result.append(self._to_char(x))
            else:
                result.append(char)
        return "".join(result)
         
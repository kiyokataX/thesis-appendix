from src.utils.math_ops import mod_inverse, extended_gcd

class AffineCipher:
    def __init__(self, a: int, b: int):
        """
        初始化仿射密码
        key = (a, b)
        加密: y = (ax + b) mod 26
        """
        self.a = a
        self.b = b
        self.m =26
        
        # --- 1.检查密钥有效性 ---
        #验证gcd(a,26) = 1,若不等于1, 就说明是无法解密的密钥
        g, _, _, = extended_gcd(self.a, self.m)
        if g != 1:
            raise ValueError(f"密钥设置错误: a={a} 与 26 不互素,无法解密!")
        
        # --- 2.预计算逆元 ---
        self.a_inv = mod_inverse(self.a, self.m)

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
                y = (self.a * x + self.b) % 26
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
                x = (self.a_inv * (y - self.b)) % 26
                result.append(self._to_char(x))
            else:
                result.append(char)
        return "".join(result)
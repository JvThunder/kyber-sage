from hashlib import shake_128, shake_256, sha3_256, sha3_512
from secrets import token_bytes
from sage.modules.free_module_element import FreeModuleElement_generic_dense
from sage.matrix.matrix_generic_dense import Matrix_generic_dense
import os

class Kyber512():
    def __init__(self, **kwargs):
        self.n = kwargs.get('n', 256)
        self.q = kwargs.get('q', 3329)
        self.k = kwargs.get('k', 2)
        self.eta_1 = kwargs.get('eta_1', 3)
        self.eta_2 = kwargs.get('eta_2', 2)
        self.d_u = kwargs.get('d_u', 10)
        self.d_v = kwargs.get('d_v', 4)
        self.secret_key_size = kwargs.get('secret_key_size', 32)
        self.zeta = kwargs.get('zeta', 17)

        PRq.<x> = PolynomialRing(GF(self.q))
        self.modulus = x^self.n + 1
        self.Rq = PRq.quotient(self.modulus)
        self.x = x
        self.zeta_powers = [int(self.Rq(self.zeta^i)) for i in range(self.n)]

    def __bytes_to_bits(self, B):
        return [B[i // 8] >> (7 - (i % 8)) & 1 for i in range(8 * len(B))]

    def __bits_to_bytes(self, B):
        return bytes([sum([B[i + j] << (7 - j) for j in range(8)]) for i in range(0, len(B), 8)])

    def __coeffs_to_poly(self, coeffs):
        return sum(self.Rq(coeffs[i] * x^i) for i in range(len(coeffs)))

    def __CBD(self, B, eta):
        beta = self.__bytes_to_bits(B)
        coeffs = [0] * 256
        for i in range(256):
            a = sum(beta[2 * i * eta + j] for j in range(eta))
            b = sum(beta[(2 * i + 1) * eta + j] for j in range(eta))
            coeffs[i] = a - b
        return self.__coeffs_to_poly(coeffs)

    def __PRF(self, seed, nonce, output_length):
        nonce_bytes = int(nonce).to_bytes(1, 'little')
        input_data = seed + nonce_bytes
        shake = shake_256(input_data)
        return shake.digest(output_length)
    
    def __decode_single(self, B, L):
        beta = self.__bytes_to_bits(B)
        coeffs = []

        for i in range(256):
            f_i = sum(beta[i * L + j] * (2 ** j) for j in range(L))
            coeffs.append(f_i)

        return self.__coeffs_to_poly(coeffs)

    def __encode_single(self, f, L):
        beta = []

        for i in range(256):
            beta_i = [(int(f[i]) >> j) & 1 for j in range(L)]
            beta.extend(beta_i)

        return self.__bits_to_bytes(beta)

    def __decode(self, byte_string, L):
        ret = []
        for i in range(0, len(byte_string), 256 * L // 8):
            ret.append(self.__decode_single(byte_string[i:i + 256 * L // 8], L))

        if len(ret) == 1:
            return ret[0]
        else:
            return vector(self.Rq, ret)

    def __encode(self, vec, L):
        if not isinstance(vec, (list, FreeModuleElement_generic_dense)):
            return self.__encode_single(vec, L)
        else:
            ret = b''
            for v in vec:
                ret += self.__encode_single(v, L)
            return ret

    def __G(self, d):
        shake = sha3_512(d).digest()
        rho = shake[:32]
        sigma = shake[32:64]
        return rho, sigma

    def __H(self, m):
        return sha3_256(m).digest()

    def __KDF(self, m, output_length = None):
        if output_length is None:
            output_length = self.secret_key_size
        shake = shake_256(m)
        return shake.digest(output_length)

    def __XOF(self, rho, i, j, output_length):
        i_bytes = int(i).to_bytes(1, 'little')
        j_bytes = int(j).to_bytes(1, 'little')
        input_data = rho + i_bytes + j_bytes
        shake = shake_128(input_data)
        return shake.digest(output_length)
    
    def __PRF(self, seed, nonce, output_length):
        nonce_bytes = int(nonce).to_bytes(1, 'little')
        input_data = seed + nonce_bytes
        shake = shake_256(input_data)
        return shake.digest(output_length)

    def bit_reverse(self, num, bits=7):
        result = 0
        for _ in range(bits):
            result = (result << 1) | (num & 1)
            num >>= 1
        return result

    def __NTT_single(self, f):
        PRq.<x> = PolynomialRing(GF(self.q))
        ret = self.Rq(0)
        for i in range(128):
            modulus = x^2 - self.zeta_powers[2*i+1]
            ntt_modulo = PRq.quotient(modulus)
            f_hat = ntt_modulo(f)
            ret += self.Rq(f_hat[1] * x^(2*i+1) + f_hat[0] * x^(2*i)) 
        return ret

    def __NTT_inv_single(self, f):
        PRq.<x> = PolynomialRing(GF(self.q))
        ret = self.Rq(0)
        for i in range(128):
            r = f[2*i+1]*x + f[2*i] 
            modulus = x^2 - self.zeta_powers[2*i+1]
            M = self.modulus // modulus
            inv_mod = M.inverse_mod(modulus)
            ret += self.Rq(r * M * inv_mod)
        return ret

    def __NTT(self, f):
        if not isinstance(f, (list, FreeModuleElement_generic_dense)):
            return self.__NTT_single(f)
        else:
            ret = []
            for v in f:
                ret.append(self.__NTT_single(v))
            return vector(self.Rq, ret)

    def __NTT_inv(self, f):
        if not isinstance(f, (list, FreeModuleElement_generic_dense)):
            return self.__NTT_inv_single(f)
        else:
            ret = []
            for v in f:
                ret.append(self.__NTT_inv_single(v))
            return vector(self.Rq, ret)

    def __NTT_product_element(self, f, g):
        PRq.<x> = PolynomialRing(GF(self.q))
        ret = self.Rq(0)
        for i in range(128):
            rf = f[2*i+1]*x + f[2*i] 
            rg = g[2*i+1]*x + g[2*i]
            modulus = x^2 - self.zeta_powers[2*i+1]
            res = (rf * rg) % modulus
            ret += self.Rq(res[1] * x^(2*i+1) + res[0] * x^(2*i))
        return ret

    def NTT_product(self, F, G):
        if type(F) == Matrix_generic_dense: # matrix
            ret = [0] * F.nrows()
            for i in range(F.nrows()):
                for j in range(F.ncols()):
                    ret[i] += self.__NTT_product_element(F[i][j], G[j])
            ret = vector(self.Rq, ret)
        elif type(F) == FreeModuleElement_generic_dense:
            ret = self.Rq(0)
            for i in range(len(F)):
                ret += self.__NTT_product_element(F[i], G[i])
        return ret

    def __parse(self, byte_stream):
        i = 0
        j = 0
        a = [0] * self.n

        while j < self.n and i+2 < len(byte_stream):
            d1 = byte_stream[i] + 256 * (byte_stream[i + 1] % 16)
            d2 = (byte_stream[i + 1] // 16) + 16 * byte_stream[i + 2]

            if d1 < self.q:
                a[j] = d1
                j += 1

            if d2 < self.q and j < self.n:
                a[j] = d2
                j += 1

            i += 3

        return self.__NTT(sum(self.Rq(a[i] * self.x^i) for i in range(self.n)))

    def __compress_single(self, f, d):
        scale_factor = (2 ** d) / self.q
        new_f = []
        
        for i in range(256):
            new_val = round(scale_factor * int(f[i])) % (2 ** d)
            new_f.append(new_val)
       
        return self.__coeffs_to_poly(new_f)

    def __decompress_single(self, f, d):
        scale_factor = self.q / (2 ** d)
        new_f = []

        for i in range(256):
            new_val = round(scale_factor * int(f[i]))
            new_f.append(new_val)

        return self.__coeffs_to_poly(new_f)

    def __compress(self, f, d):
        if not isinstance(f, (list, FreeModuleElement_generic_dense)):
            return self.__compress_single(f, d)
        else:
            ret = []
            for e in f:
                ret.append(self.__compress_single(e, d))
            return vector(self.Rq, ret)

    def __decompress(self, f, d):
        if not isinstance(f, (list, FreeModuleElement_generic_dense)):
            return self.__decompress_single(f, d)
        else:
            ret = []
            for e in f:
                ret.append(self.__decompress_single(e, d))
            return vector(self.Rq, ret)

    def generate_key(self):
        d = token_bytes(32)
        rho, sigma = self.__G(d)
        N = 0
        A_hat = Matrix([[self.__parse(self.__XOF(rho, j, i, 64 * self.eta_1)) 
                    for j in range(self.k)] for i in range(self.k)])

        s = []
        for i in range(self.k):
            s.append(self.__CBD(self.__PRF(sigma, N, 64 * self.eta_1), self.eta_1))
            N += 1
        
        e = []
        for i in range(self.k):
            e.append(self.__CBD(self.__PRF(sigma, N, 64 * self.eta_1), self.eta_1))
            N += 1

        s_hat = self.__NTT(s)
        e_hat = self.__NTT(e)
        t_hat = self.NTT_product(A_hat, s_hat) + e_hat

        pk = self.__encode(t_hat, 12) + rho
        sk = self.__encode(s_hat, 12)
        return pk, sk

    def encrypt(self, pk, m, r):
        t = pk[:-32]
        rho = pk[-32:]
        t_hat = self.__decode(t, 12)
        A_hat = Matrix([[self.__parse(self.__XOF(rho, i, j, 64 * self.eta_1)) 
                    for j in range(self.k)] for i in range(self.k)])

        N = 0
        r_vec = []
        for i in range(self.k):
            r_vec.append(self.__CBD(self.__PRF(r, N, 64 * self.eta_1), self.eta_1))
            N += 1
        e1_vec = []
        for i in range(self.k):
            e1_vec.append(self.__CBD(self.__PRF(r, N, 64 * self.eta_2), self.eta_2))
            N += 1
        e1_hat = vector(self.Rq, e1_vec)
        e2 = self.__CBD(self.__PRF(r, N, 64 * self.eta_2), self.eta_2)
            
        r_hat = self.__NTT(r_vec)
        u_hat = self.__NTT_inv(self.NTT_product(A_hat, r_hat)) + e1_hat
        v = self.__NTT_inv(self.NTT_product(t_hat, r_hat)) + e2 + self.__decompress(self.__decode(m, 1), 1)

        comp_u = [self.__compress(u_hat[i],  self.d_u) for i in range(len(u_hat))]
        comp_v = self.__compress(v, self.d_v)
        c1 = self.__encode(comp_u,  self.d_u)
        c2 = self.__encode(comp_v,  self.d_v)
        ciphertext = c1 + c2

        return ciphertext

    def decrypt(self, sk, c):
        c1 = c[:-256 * self.d_v // 8]
        c2 = c[-256 * self.d_v // 8:]
        u_hat = self.__decompress(self.__decode(c1, self.d_u), self.d_u)
        v = self.__decompress(self.__decode(c2, self.d_v), self.d_v)
        s_hat = self.__decode(sk, 12)
        m = self.__encode(self.__compress(
            v - self.__NTT_inv(self.NTT_product(s_hat, self.__NTT(u_hat))), 1), 1
        )
        return m

    def ccakem_generate_key(self):
        z = token_bytes(32)
        pk, sk_prime = self.generate_key()
        sk = sk_prime + pk + self.__H(pk) + z
        return pk, sk

    def ccakem_encrypt(self, pk):
        m = token_bytes(32)
        m = self.__H(m)
        K, r = self.__G(m + self.__H(pk))
        c = self.encrypt(pk, m, r)
        K = self.__KDF(K + self.__H(c))
        return c, K

    def ccakem_decrypt(self, c, sk):
        pk_start_idx = 12 * self.k * self.n // 8
        h_start_idx = 24 * self.k * self.n // 8 + 32
        z_start_idx = h_start_idx + 32
        pk = sk[pk_start_idx:h_start_idx]
        h = sk[h_start_idx:z_start_idx]
        z = sk[z_start_idx:]
        sk = sk[:pk_start_idx]
        m_prime = self.decrypt(sk, c)
        K_prime, r_prime = self.__G(m_prime + h)
        c_prime = self.encrypt(pk, m_prime, r_prime)
        if c == c_prime:
            return self.__KDF(K_prime + self.__H(c))
        else:
            return self.__KDF(z + self.__H(c))    
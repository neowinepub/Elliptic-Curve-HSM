#소프트웨어 ECC에 serial 통신 연결
import serial
import sys
from PyQt5.QtWidgets import *
from PyQt5.uic import *
import collections
import random
import hashlib
import binascii
import string


EllipticCurve = collections.namedtuple('EllipticCurve', 'name p p_num a a_num b b_num g g_num n n_num h r len')  # 이건 머지?
curve_p192 = EllipticCurve(
    'curve p-192',
    # Field characteristic.
    p='FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF',
    # Curve coefficients.
    p_num = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF,
    a='FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC',
    a_num = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC,
    b='64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1',
    b_num = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1,
    # Base point
    g=('188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012',
       '07192B95FFC8DA78631011ED6B24CDD573F977A11E794811'),# 튜플:리스트와 비슷하지만 변경되지 않는다.
    g_num=(0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012,
           0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811),
    # Subgroup order.
    n=0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831,
    n_num = 'FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831',
    # Subgroup cofactor.
    h=1,
    r = '100000000000000020000000000000001',
    len ='0',

)
curve_p224 = EllipticCurve(
    'curve p-224',
    # Field characteristic.
    p='FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001',
    # Curve coefficients.
    p_num = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001,

    a='FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE',
    a_num = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE,

    b='B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4',
    b_num = 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4,
    # Base point
    g=('B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21',
       'BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34'),# 튜플:리스트와 비슷하지만 변경되지 않는다.
    g_num=(0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21,
           0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34),
    # Subgroup order.
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D,
    n_num = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D',
    # Subgroup cofactor.
    h=1,
    r = 'FFFFFFFFFFFFFFFFFFFFFFFE000000000000000000000001',
    len ='1',
)

curve_p256 = EllipticCurve(
    'curve p-256',
    # Field characteristic.
    p='FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF',
    # Curve coefficients.
    p_num = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a='FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC',
    a_num = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    b='5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B',
    b_num = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    # Base point
    g=('6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296',
       '4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5'),# 튜플:리스트와 비슷하지만 변경되지 않는다.
    g_num=(0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
           0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5),
    # Subgroup order.
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    n_num = 'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
    # Subgroup cofactor.
    h=1,
    r = '4FFFFFFFDFFFFFFFFFFFFFFFEFFFFFFFBFFFFFFFF0000000000000003',
    len ='2',
)

curve_p384 = EllipticCurve(
    'curve p-384',
    # Field characteristic.
    p='FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF',
    # Curve coefficients.
    p_num = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
    a='FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC',
    a_num = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
    b='B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF',
    b_num = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    # Base point
    g=('AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7',
       '3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F'),# 튜플:리스트와 비슷하지만 변경되지 않는다.
    g_num=(0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
           0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F),
    # Subgroup order.
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
    n_num = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973',
    # Subgroup cofactor.
    h=1,
    r = '10000000200000000FFFFFFFE000000000000000200000000FFFFFFFE00000001',
    len='3',
)

curve_p521 = EllipticCurve(
    'curve p-521',
    # Field characteristic.
    p='000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
    # Curve coefficients.
    p_num = 0x000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
    a='000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC',
    a_num = 0x000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC,
    b='0000051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00',
    b_num = 0x0000051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,
    # Base point
    g=('000000C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66',
       '0000011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650'),# 튜플:리스트와 비슷하지만 변경되지 않는다.
    g_num=(0x000000C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
           0x0000011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650),
    # Subgroup order.
    n=0x000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
    n_num = '000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409',
    # Subgroup cofactor.
    h=1,
    r = '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000',
    len='4',
)



RSA = collections.namedtuple('RSA', 'name e e_num r len')

RSA_1024 = RSA(
    'RSA',
    e = '10001',
    e_num = 0x10001,
    r = pow(2, 1024),
    len='5',

)

RSA_2048 = RSA(
    'RSA',
    e = '10001',
    e_num = 0x10001,
    r = pow(2, 2048),
    len='6',
)

RSA_4096 = RSA(
    'RSA',
    e = '10001',
    e_num = 0x10001,
    r = pow(2, 4096),
    len='7',
)

class EventDemo(QWidget):
    def __init__(self):
        super().__init__()
        self.ui = loadUi("ElGamal3.ui", self)
        self.show()
        self.ecc_192.clicked.connect(self.ECparameter_p192)
        self.ecc_224.clicked.connect(self.ECparameter_p224)
        self.ecc_256.clicked.connect(self.ECparameter_p256)
        self.ecc_384.clicked.connect(self.ECparameter_p384)
        self.ecc_521.clicked.connect(self.ECparameter_p521)

        self.ecdsa_192.clicked.connect(self.ECDSAParameter_p192)
        self.ecdsa_224.clicked.connect(self.ECDSAParameter_p224)
        self.ecdsa_256.clicked.connect(self.ECDSAParameter_p256)
        self.ecdsa_384.clicked.connect(self.ECDSAParameter_p384)
        self.ecdsa_521.clicked.connect(self.ECDSAParameter_p521)

        self.el_192.clicked.connect(self.ELparameter_p192)
        self.el_224.clicked.connect(self.ELparameter_p224)
        self.el_256.clicked.connect(self.ELparameter_p256)
        self.el_384.clicked.connect(self.ELparameter_p384)
        self.el_521.clicked.connect(self.ELparameter_p521)

        self.pb_clear.clicked.connect(self.clearf)
        #------------ECC------------------------#
        self.pb_rng.clicked.connect(self.ecc_rng)
        self.pb_alice_pk.clicked.connect(self.alice_pk)
        self.pb_bob_pk.clicked.connect(self.bob_pk)
        self.pb_alice_s.clicked.connect(self.alice_secret)
        self.pb_bob_s.clicked.connect(self.bob_secret)
        self.p21.clicked.connect(self.clickMethod)
       
  
        # ------------EC-elgmal--------------------#
        self.el_Pa.clicked.connect(self.el_rng)
        self.el_gen.clicked.connect(self.el_PPgen)
        self.el_en.clicked.connect(self.el_encryption)
        self.el_de.clicked.connect(self.el_decryption)
      
    

        #--------------------ECDSA------------------#
        self.k_gen.clicked.connect(self.ecdsa_rng)
        self.pub_gen_2.clicked.connect(self.ecdsa_sha)
        self.pub_gen.clicked.connect(self.ecdsa_pub_gen)
        self.r_gen.clicked.connect(self.ecdsa_decode)


        self.alice_secret_x = None
        self.alice_secret_y = None
        self.bob_secret_x = None
        self.bob_secret_y = None

    def clickMethod(self):
        f= self.t2.toPlainText()
        print(f)
        a = int(f, 16)

        print(a)
        c =  hex(a)
        print(c)

    def ECDSAParameter_p192(self):
        self.a = curve_p192.a.zfill(48)
        self.b = curve_p192.b.zfill(48)
        self.a_num = curve_p192.a_num
        self.b_num = curve_p192.b_num
        self.len = curve_p192.len

        self.gx, self.gy = curve_p192.g
        self.gx_num, self.gy_num = curve_p192.g_num
        self.p = curve_p192.p
        self.p_num = curve_p192.p_num
        self.rs = curve_p192.r
        self.n = curve_p192.n
        self.n_lit = curve_p192.n_num
        self.el_Rk_3.setText(self.n_lit)
        #self.el_gx_2.setText(self.gx)
        #self.el_gy_2.setText(self.gy)
        self.el_Rk_2.setText(self.p)
        self.curve_mode = 0
        self.curve_div_4 = 48
        self.curve_length = 192
      

    def ECDSAParameter_p224(self):
        self.a = curve_p224.a.zfill(56)
        self.b = curve_p224.b.zfill(56)
        self.a_num = curve_p224.a_num
        self.b_num = curve_p224.b_num
        self.len = curve_p224.len
        self.gx, self.gy = curve_p224.g
        self.gx_num, self.gy_num = curve_p224.g_num
        self.p = curve_p224.p
        self.p_num = curve_p224.p_num
        self.rs = curve_p224.r
        self.n = curve_p224.n
        self.n_lit = curve_p224.n_num
        self.el_Rk_3.setText(self.n_lit)
        #self.el_gx_2.setText(self.gx)
        #self.el_gy_2.setText(self.gy)
        self.el_Rk_2.setText(self.p)
        self.curve_mode = 1
        self.curve_div_4 = 56
        self.curve_length = 224
     
    

    def ECDSAParameter_p256(self):
        self.a = curve_p256.a.zfill(64)
        self.b = curve_p256.b.zfill(64)
        self.a_num = curve_p256.a_num
        self.b_num = curve_p256.b_num
        self.len = curve_p256.len
        self.gx, self.gy = curve_p256.g
        self.gx_num, self.gy_num = curve_p256.g_num
        self.p = curve_p256.p
        self.p_num = curve_p256.p_num
        self.rs = curve_p256.r
        self.n = curve_p256.n
        self.n_lit = curve_p256.n_num
        self.el_Rk_3.setText(self.n_lit)
        #self.el_gx_2.setText(self.gx)
        #self.el_gy_2.setText(self.gy)
        self.el_Rk_2.setText(self.p)
        self.curve_mode = 2
        self.curve_div_4 = 64
        self.curve_length = 256
    
    

    def ECDSAParameter_p384(self):
        self.a = curve_p384.a.zfill(96)
        self.b = curve_p384.b.zfill(96)
        self.a_num = curve_p384.a_num
        self.b_num = curve_p384.b_num
        self.len = curve_p384.len
        self.gx, self.gy = curve_p384.g
        self.gx_num, self.gy_num = curve_p384.g_num
        self.p = curve_p384.p
        self.p_num = curve_p384.p_num
        self.rs = curve_p384.r
        self.n = curve_p384.n
        self.n_lit = curve_p384.n_num
        self.el_Rk_3.setText(self.n_lit)
        #self.el_gx_2.setText(self.gx)
        #self.el_gy_2.setText(self.gy)
        self.el_Rk_2.setText(self.p)
        self.curve_mode = 3
        self.curve_div_4 = 96
        self.curve_length = 384

    

    def ECDSAParameter_p521(self):
        self.a = curve_p521.a.zfill(136)
        self.b = curve_p521.b.zfill(136)
        self.a_num = curve_p521.a_num
        self.b_num = curve_p521.b_num
        self.len = curve_p521.len
        self.gx, self.gy = curve_p521.g
        self.gx_num, self.gy_num = curve_p521.g_num
        self.p = curve_p521.p
        self.p_num = curve_p521.p_num
        self.rs = curve_p521.r
        self.n = curve_p521.n
        self.n_lit = curve_p521.n_num
        self.el_Rk_3.setText(self.n_lit)
        #self.el_gx_2.setText(self.gx)
        #self.el_gy_2.setText(self.gy)
        self.el_Rk_2.setText(self.p)
        self.curve_mode = 4
        self.curve_div_4 = 136
        self.curve_length = 544
     


    def ECparameter_p192(self):
        self.a = curve_p192.a.zfill(48)
        self.b = curve_p192.b.zfill(48)
        self.a_num = curve_p192.a_num
        self.b_num = curve_p192.b_num
        self.len = curve_p192.len
        self.gx, self.gy = curve_p192.g
        self.gx_num, self.gy_num = curve_p192.g_num
        self.p = curve_p192.p
        self.p_num = curve_p192.p_num
        self.rs = curve_p192.r
        self.edit_gx.setText(self.gx)
        self.edit_gy.setText(self.gy)
        self.edit_p.setText(self.p)
        self.curve_mode = 0
        self.curve_div_4 = 48
        self.curve_length = 192


    def ECparameter_p224(self):
        self.a = curve_p224.a.zfill(56)
        self.b = curve_p224.b.zfill(56)
        self.a_num = curve_p224.a_num
        self.b_num = curve_p224.b_num
        self.len = curve_p224.len
        self.gx, self.gy = curve_p224.g
        self.gx_num, self.gy_num = curve_p224.g_num
        self.p = curve_p224.p
        self.p_num = curve_p224.p_num
        self.rs = curve_p224.r
        self.edit_gx.setText(self.gx)
        self.edit_gy.setText(self.gy)
        self.edit_p.setText(self.p)
        self.curve_mode = 1
        self.curve_div_4 = 56
        self.curve_length = 224

    def ECparameter_p256(self):
        self.a = curve_p256.a.zfill(64)
        self.b = curve_p256.b.zfill(64)
        self.a_num = curve_p256.a_num
        self.b_num = curve_p256.b_num
        self.len = curve_p256.len
        self.gx, self.gy = curve_p256.g
        self.gx_num, self.gy_num = curve_p256.g_num
        self.p = curve_p256.p
        self.p_num = curve_p256.p_num
        self.rs = curve_p256.r
        self.edit_gx.setText(self.gx)
        self.edit_gy.setText(self.gy)
        self.edit_p.setText(self.p)
        self.curve_mode = 2
        self.curve_div_4 = 64
        self.curve_length = 256

    def ECparameter_p384(self):
        self.a = curve_p384.a.zfill(96)
        self.b = curve_p384.b.zfill(96)
        self.a_num = curve_p384.a_num
        self.b_num = curve_p384.b_num
        self.len = curve_p384.len
        self.gx, self.gy = curve_p384.g
        self.gx_num, self.gy_num = curve_p384.g_num
        self.p = curve_p384.p
        self.p_num = curve_p384.p_num
        self.rs = curve_p384.r
        self.edit_gx.setText(self.gx)
        self.edit_gy.setText(self.gy)
        self.edit_p.setText(self.p)
        self.curve_mode = 3
        self.curve_div_4 = 96
        self.curve_length = 384

    def ECparameter_p521(self):
        self.a = curve_p521.a.zfill(136)
        self.b = curve_p521.b.zfill(136)
        self.a_num = curve_p521.a_num
        self.b_num = curve_p521.b_num
        self.len = curve_p521.len
        self.gx, self.gy = curve_p521.g
        self.gx_num, self.gy_num = curve_p521.g_num
        self.p = curve_p521.p
        self.p_num = curve_p521.p_num
        self.rs = curve_p521.r
        self.edit_gx.setText(self.gx)
        self.edit_gy.setText(self.gy)
        self.edit_p.setText(self.p)
        self.curve_mode = 4
        self.curve_div_4 = 136
        self.curve_length = 544

    def ECparameter_1024(self):
        self.in_e = RSA_1024.e.zfill(256)
        self.e = RSA_1024.e
        self.e_num = RSA_1024.e_num
        self.key_mode= 0
        self.curve_div_4 = 256
        self.key_length = 1024
        self.r = RSA_1024.r
        self.len = RSA_1024.len

    def ECparameter_2048(self):
        self.in_e = RSA_2048.e.zfill(512)
        self.e = RSA_2048.e
        self.e_num = RSA_2048.e_num
        self.key_mode= 1
        self.curve_div_4 = 512
        self.key_length = 2048
        self.r = RSA_2048.r
        self.len = RSA_2048.len

    def ECparameter_4096(self):
        self.in_e = RSA_4096.e.zfill(1024)
        self.e = RSA_4096.e
        self.e_num = RSA_4096.e_num
        self.key_mode= 2
        self.curve_div_4 = 1024
        self.key_length = 4096
        self.r = RSA_4096.r
        self.len = RSA_4096.len

    def DSAparameter_p192(self):
        self.a = curve_p192.a.zfill(48)
        self.b = curve_p192.b.zfill(48)
        self.a_num = curve_p192.a_num
        self.b_num = curve_p192.b_num
        self.len = curve_p192.len
        self.gx, self.gy = curve_p192.g
        self.gx_num, self.gy_num = curve_p192.g_num
        self.p = curve_p192.p
        self.p_num = curve_p192.p_num
        self.rs = curve_p192.r
        #self.edit_gx.setText(self.gx)
        #self.edit_gy.setText(self.gy)
        #self.edit_p.setText(self.p)
        self.curve_mode = 0
        self.curve_div_4 = 48
        self.curve_length = 192
        self.RbR.setChecked(True)

    def DSAparameter_p224(self):
        self.a = curve_p224.a.zfill(56)
        self.b = curve_p224.b.zfill(56)
        self.a_num = curve_p224.a_num
        self.b_num = curve_p224.b_num
        self.len = curve_p224.len
        self.gx, self.gy = curve_p224.g
        self.gx_num, self.gy_num = curve_p224.g_num
        self.p = curve_p224.p
        self.p_num = curve_p224.p_num
        self.rs = curve_p224.r
        self.edit_gx.setText(self.gx)
        self.edit_gy.setText(self.gy)
        self.edit_p.setText(self.p)
        self.curve_mode = 1
        self.curve_div_4 = 56
        self.curve_length = 224
        self.RbR.setChecked(True)

    def DSAparameter_p256(self):
        self.a = curve_p256.a.zfill(64)
        self.b = curve_p256.b.zfill(64)
        self.a_num = curve_p256.a_num
        self.b_num = curve_p256.b_num
        self.len = curve_p256.len
        self.gx, self.gy = curve_p256.g
        self.gx_num, self.gy_num = curve_p256.g_num
        self.n_lit = curve_p256.n_num
        self.n = curve_p256.n
        self.p = curve_p256.p
        self.p_num = curve_p256.p_num
        self.rs = curve_p256.r
        self.edit_gx.setText(self.gx)
        self.edit_gy.setText(self.gy)
        self.edit_p.setText(self.p)
        self.curve_mode = 2
        self.curve_div_4 = 64
        self.curve_length = 256
        self.RbR.setChecked(True)

    def DSAparameter_p384(self):
        self.a = curve_p384.a.zfill(96)
        self.b = curve_p384.b.zfill(96)
        self.a_num = curve_p384.a_num
        self.b_num = curve_p384.b_num
        self.len = curve_p384.len
        self.gx, self.gy = curve_p384.g
        self.gx_num, self.gy_num = curve_p384.g_num
        self.p = curve_p384.p
        self.p_num = curve_p384.p_num
        self.rs = curve_p384.r
        self.edit_gx.setText(self.gx)
        self.edit_gy.setText(self.gy)
        self.edit_p.setText(self.p)
        self.curve_mode = 3
        self.curve_div_4 = 96
        self.curve_length = 384
        self.RbR.setChecked(True)

    def DSAparameter_p521(self):
        self.a = curve_p521.a.zfill(136)
        self.b = curve_p521.b.zfill(136)
        self.a_num = curve_p521.a_num
        self.b_num = curve_p521.b_num
        self.len = curve_p521.len
        self.gx, self.gy = curve_p521.g
        self.gx_num, self.gy_num = curve_p521.g_num
        self.p = curve_p521.p
        self.p_num = curve_p521.p_num
        self.rs = curve_p521.r
        self.edit_gx.setText(self.gx)
        self.edit_gy.setText(self.gy)
        self.edit_p.setText(self.p)
        self.curve_mode = 4
        self.curve_div_4 = 136
        self.curve_length = 544
        self.RbR.setChecked(True)

    def ELparameter_p192(self):
        self.a = curve_p192.a.zfill(48)
        self.b = curve_p192.b.zfill(48)
        self.a_num = curve_p192.a_num
        self.b_num = curve_p192.b_num
        self.len = curve_p192.len
        self.gx, self.gy = curve_p192.g
        self.gx_num, self.gy_num = curve_p192.g_num
        self.p = curve_p192.p
        self.p_num = curve_p192.p_num
        self.rs = curve_p192.r
        # self.edit_gx.setText(self.gx)
        # self.edit_gy.setText(self.gy)
        # self.edit_p.setText(self.p)
        self.curve_mode = 0
        self.curve_div_4 = 48
        self.curve_length = 192

    def ELparameter_p224(self):
        self.a = curve_p224.a.zfill(56)
        self.b = curve_p224.b.zfill(56)
        self.a_num = curve_p224.a_num
        self.b_num = curve_p224.b_num
        self.len = curve_p224.len
        self.gx, self.gy = curve_p224.g
        self.gx_num, self.gy_num = curve_p224.g_num
        self.p = curve_p224.p
        self.p_num = curve_p224.p_num
        self.rs = curve_p224.r
        self.edit_gx.setText(self.gx)
        self.edit_gy.setText(self.gy)
        self.edit_p.setText(self.p)
        self.curve_mode = 1
        self.curve_div_4 = 56
        self.curve_length = 224

    def ELparameter_p256(self):
        self.a = curve_p256.a.zfill(64)
        self.b = curve_p256.b.zfill(64)
        self.a_num = curve_p256.a_num
        self.b_num = curve_p256.b_num
        self.len = curve_p256.len
        self.gx, self.gy = curve_p256.g
        self.gx_num, self.gy_num = curve_p256.g_num
        self.p = curve_p256.p
        self.p_num = curve_p256.p_num
        self.rs = curve_p256.r
        self.edit_gx.setText(self.gx)
        self.edit_gy.setText(self.gy)
        self.edit_p.setText(self.p)
        self.curve_mode = 2
        self.curve_div_4 = 64
        self.curve_length = 256

    def ELparameter_p384(self):
        self.a = curve_p384.a.zfill(96)
        self.b = curve_p384.b.zfill(96)
        self.a_num = curve_p384.a_num
        self.b_num = curve_p384.b_num
        self.len = curve_p384.len
        self.gx, self.gy = curve_p384.g
        self.gx_num, self.gy_num = curve_p384.g_num
        self.p = curve_p384.p
        self.p_num = curve_p384.p_num
        self.rs = curve_p384.r
        self.edit_gx.setText(self.gx)
        self.edit_gy.setText(self.gy)
        self.edit_p.setText(self.p)
        self.curve_mode = 3
        self.curve_div_4 = 96
        self.curve_length = 384

    def ELparameter_p521(self):
        self.a = curve_p521.a.zfill(136)
        self.b = curve_p521.b.zfill(136)
        self.a_num = curve_p521.a_num
        self.b_num = curve_p521.b_num
        self.len = curve_p521.len
        self.gx, self.gy = curve_p521.g
        self.gx_num, self.gy_num = curve_p521.g_num
        self.p = curve_p521.p
        self.p_num = curve_p521.p_num
        self.rs = curve_p521.r
        self.edit_gx.setText(self.gx)
        self.edit_gy.setText(self.gy)
        self.edit_p.setText(self.p)
        self.curve_mode = 4
        self.curve_div_4 = 136
        self.curve_length = 544

    def ECSM_mode_parameter(self):
        self.op_mode =  '0'
        self.op_mode_num = 0x0
        self.ec_gx.setText(self.gx)
        self.ec_gy.setText(self.gy)
        self.ec_p.setText(self.p)
        self.etc_a.setText("")
        self.etc_b.setText("")
        #self.etc_p.setText("")
        self.etc_soft.setText("")
        self.etc_hard.setText("")
        self.etc_matched.setText("")

    def ECA_mode_parameter(self):
        self.op_mode =  '1'
        self.op_mode_num = 0x1
        self.ec_gx.setText("")
        self.ec_gy.setText("")
        self.ec_px.setText("")
        self.ec_py.setText("")
        self.ec_p.setText(self.p)
        self.etc_a.setText("")
        self.etc_b.setText("")
        #self.etc_p.setText("")
        self.etc_soft.setText("")
        self.etc_hard.setText("")
        self.etc_matched.setText("")

    def ECD_mode_parameter(self):
        self.op_mode =  '2'
        self.op_mode_num = 0x2
        self.ec_p.setText(self.p)
        self.ec_gx.setText("")
        self.ec_gy.setText("")
        self.ec_px.setText("")
        self.ec_py.setText("")
        self.etc_a.setText("")
        self.etc_b.setText("")
        #self.etc_p.setText("")
        self.etc_soft.setText("")
        self.etc_hard.setText("")
        self.etc_matched.setText("")

    def ECS_mode_parameter(self):
        self.op_mode =  '8'
        self.op_mode_num = 0x8
        self.ec_gx.setText("")
        self.ec_gy.setText("")
        self.ec_px.setText("")
        self.ec_py.setText("")
        self.ec_p.setText(self.p)
        self.etc_a.setText("")
        self.etc_b.setText("")
        #self.etc_p.setText("")
        self.etc_soft.setText("")
        self.etc_hard.setText("")
        self.etc_matched.setText("")

    def MA_mode_parameter(self):
        self.op_mode =  '3'
        self.op_mode_num = 0x3
        #self.etc_p.setText(self.p)
        self.ec_gx.setText("")
        self.ec_gy.setText("")
        self.ec_p.setText("")
        self.ec_key.setText("")
        self.ec_px_h.setText("")
        self.ec_py_h.setText("")
        self.ec_px_s.setText("")
        self.ec_py_s.setText("")
        self.ec_matched.setText("")
        self.ec_px.setText("")
        self.ec_py.setText("")

    def MS_mode_parameter(self):
        self.op_mode = '4'
        self.op_mode_num = 0x4
        #self.etc_p.setText(self.p)
        self.ec_gx.setText("")
        self.ec_gy.setText("")
        self.ec_p.setText("")
        self.ec_key.setText("")
        self.ec_px_h.setText("")
        self.ec_py_h.setText("")
        self.ec_px_s.setText("")
        self.ec_py_s.setText("")
        self.ec_matched.setText("")
        self.ec_px.setText("")
        self.ec_py.setText("")

    def MM_mode_parameter(self):
        self.op_mode = '5'
        self.op_mode_num = 0x5
        #self.ec_p.setText(self.p)
        self.ec_gx.setText("")
        self.ec_gy.setText("")
        self.ec_p.setText("")
        self.ec_key.setText("")
        self.ec_px_h.setText("")
        self.ec_py_h.setText("")
        self.ec_px_s.setText("")
        self.ec_py_s.setText("")
        self.ec_matched.setText("")
        self.ec_px.setText("")
        self.ec_py.setText("")

    def MD_mode_parameter(self):
        self.op_mode = '6'
        self.op_mode_num = 0x6
        #self.etc_p.setText(self.p)
        self.ec_gx.setText("")
        self.ec_gy.setText("")
        self.ec_p.setText("")
        self.ec_key.setText("")
        self.ec_px_h.setText("")
        self.ec_py_h.setText("")
        self.ec_px_s.setText("")
        self.ec_py_s.setText("")
        self.ec_matched.setText("")
        self.ec_px.setText("")
        self.ec_py.setText("")

    def MI_mode_parameter(self):
        self.op_mode = '7'
        self.op_mode_num = 0x7
        #self.etc_p.setText(self.p)
        self.ec_gx.setText("")
        self.ec_gy.setText("")
        self.ec_p.setText("")
        self.ec_key.setText("")
        self.ec_px_h.setText("")
        self.ec_py_h.setText("")
        self.ec_px_s.setText("")
        self.ec_py_s.setText("")
        self.ec_matched.setText("")
        self.ec_px.setText("")
        self.ec_py.setText("")

    def clearf(self):
        self.el_gx_2.setText("")
        self.el_gx_4.setText("")
        self.el_Sx_3.setText("")
        self.el_gx_5.setText("")
        self.el_gx_11.setText("")
        self.el_gx_6.setText("")
        self.el_gx_13.setText("")
        self.el_gx_9.setText("")
        self.el_gy_2.setText("")
        self.el_gx_7.setText("")
        self.el_gx_12.setText("")
        self.el_gx_8.setText("")
        self.el_gx_10.setText("")
        self.el_Sx_4.setText("")
        self.el_Sx_2.setText("")
        self.el_Rk_2.setText("")
        self.el_Rk_3.setText("")
    
        self.edit_matched.setText("")
        self.edit_pax.setText("")
        self.edit_pay.setText("")
        self.edit_secretax.setText("")
        self.edit_secretay.setText("")
        self.edit_gx.setText("")
        self.edit_gy.setText("")
        self.edit_ka.setText("")
        self.edit_kb.setText("")
        self.edit_p.setText("")
        self.edit_pbx.setText("")
        self.edit_pby.setText("")
        self.edit_secretbx.setText("")
        self.edit_secretby.setText("")

        self.el_CRx.setText("")
        self.el_CRy.setText("asdf")
        self.el_CSx.setText("")
        self.el_CSy.setText("")
        self.el_DMx.setText("")
        self.el_DMy.setText("")
        self.el_Rk.setText("")
        self.el_Sx.setText("")
        self.el_gx.setText("")
        self.el_gy.setText("")
        self.el_ply.setText("")
        self.el_plx.setText("")
        self.el_pux.setText("")
        self.el_puy.setText("")
        self.el_veri.setText("")


    def decimal_to_rdecimal(self, curve_div_4, data_dtd):
        real_result = 0
        k = 0
        for i in range(curve_div_4-1, -1, -1):
            if data_dtd[i] == 48:
                result = 0
            elif data_dtd[i] == 49:
                result = 1
            elif data_dtd[i] == 50:
                result = 2
            elif data_dtd[i] == 51:
                result = 3
            elif data_dtd[i] == 52:
                result = 4
            elif data_dtd[i] == 53:
                result = 5
            elif data_dtd[i] == 54:
                result = 6
            elif data_dtd[i] == 55:
                result = 7
            elif data_dtd[i] == 56:
                result = 8
            elif data_dtd[i] == 57:
                result = 9
            elif data_dtd[i] == 65:
                result = 10
            elif data_dtd[i] == 66:
                result = 11
            elif data_dtd[i] == 67:
                result = 12
            elif data_dtd[i] == 68:
                result = 13
            elif data_dtd[i] == 69:
                result = 14
            elif data_dtd[i] == 70:
                result = 15

            real_result = real_result + (result*(16**k))
            k = k +1

        return real_result

    def ecc_rng(self):
        if self.curve_mode == 0:
            self.alice_private_key = random.randrange(pow(2,191), curve_p192.p_num)
            self.edit_ka.setText(str(format(self.alice_private_key,'x')).upper())
            self.bob_private_key = random.randrange(pow(2,191), curve_p192.p_num)
            self.edit_kb.setText(str(format(self.bob_private_key, 'x')).upper())
        elif self.curve_mode == 1:
            self.alice_private_key = random.randrange(pow(2,223), curve_p224.p_num)
            self.edit_ka.setText(str(format(self.alice_private_key, 'x')).upper())
            self.bob_private_key = random.randrange(pow(2,223), curve_p224.p_num)
            self.edit_kb.setText(str(format(self.bob_private_key, 'x')).upper())
        elif self.curve_mode == 2:
            self.alice_private_key = random.randrange(pow(2,255), curve_p256.p_num)
            self.edit_ka.setText(str(format(self.alice_private_key, 'x')).lower())
            self.bob_private_key = random.randrange(pow(2,255), curve_p256.p_num)
            self.edit_kb.setText(str(format(self.bob_private_key, 'x')).lower())
        elif self.curve_mode == 3:
            self.alice_private_key = random.randrange(pow(2,383), curve_p384.p_num)
            self.edit_ka.setText(str(format(self.alice_private_key, 'x')).upper())
            self.bob_private_key = random.randrange(pow(2,383), curve_p384.p_num)
            self.edit_kb.setText(str(format(self.bob_private_key, 'x')).upper())
        elif self.curve_mode == 4:
            self.alice_private_key = random.randrange(pow(2,520), curve_p521.p_num)
            self.edit_ka.setText(str(format(self.alice_private_key, 'x')).upper())
            self.bob_private_key = random.randrange(pow(2,520), curve_p521.p_num)
            self.edit_kb.setText(str(format(self.bob_private_key, 'x')).upper())

    def ec_rng(self):
        if self.curve_mode == 0:
            self.alice_key = random.randrange(pow(2,191), curve_p192.p_num)
            self.ec_key.setText(str(format(self.alice_key,'x')).upper())
        elif self.curve_mode == 1:
            self.alice_key = random.randrange(pow(2,223), curve_p224.p_num)
            self.ec_key.setText(str(format(self.alice_key, 'x')).upper())
        elif self.curve_mode == 2:
            self.alice_key = random.randrange(pow(2,255), curve_p256.p_num)
            self.ec_key.setText(str(format(self.alice_key, 'x')).upper())
        elif self.curve_mode == 3:
            self.alice_key = random.randrange(pow(2,383), curve_p384.p_num)
            self.ec_key.setText(str(format(self.alice_key, 'x')).upper())
        elif self.curve_mode == 4:
            self.alice_key = random.randrange(pow(2,520), curve_p521.p_num)
            self.ec_key.setText(str(format(self.alice_key, 'x')).upper())

    def el_rng(self):
        if self.curve_mode == 0:
            self.Sx = random.randrange(pow(2,191), curve_p192.p_num)
            self.Rk = random.randrange(pow(2,191), curve_p192.p_num)
            self.Pk = random.randrange(pow(2,191), curve_p192.p_num)
            print('Pk : ',hex(self.Pk))
            self.el_Sx.setText(str(format(self.Sx, 'x')).upper())
            self.el_Rk.setText(str(format(self.Rk, 'x')).upper())
            self.el_gx.setText(self.gx)
            self.el_gy.setText(self.gy)
        elif self.curve_mode == 1:
            self.Sx = random.randrange(pow(2,223), curve_p224.p_num)
            self.Rk = random.randrange(pow(2,223), curve_p224.p_num)
            self.Pk = random.randrange(pow(2,223), curve_p224.p_num)
            print('Pk : ', hex(self.Pk))
            self.el_gx.setText(self.gx)
            self.el_gy.setText(self.gy)
            self.el_Sx.setText(str(format(self.Sx, 'x')).upper())
            self.el_Rk.setText(str(format(self.Rk, 'x')).upper())
        elif self.curve_mode == 2:
            self.Sx = random.randrange(pow(2,255), curve_p256.p_num)
            self.Rk = random.randrange(pow(2,255), curve_p256.p_num)
            self.Pk = random.randrange(pow(2,255), curve_p256.p_num)
            print('Pk : ', hex(self.Pk))
            self.el_gx.setText(self.gx)
            self.el_gy.setText(self.gy)
            self.el_Sx.setText(str(format(self.Sx, 'x')).lower())
            self.el_Rk.setText(str(format(self.Rk, 'x')).lower())
        elif self.curve_mode == 3:
            self.Sx = random.randrange(pow(2,383), curve_p384.p_num)
            self.Rk = random.randrange(pow(2,383), curve_p384.p_num)
            self.Pk = random.randrange(pow(2,383), curve_p384.p_num)
            print('Pk : ', hex(self.Pk))
            self.el_gx.setText(self.gx)
            self.el_gy.setText(self.gy)
            self.el_Sx.setText(str(format(self.Sx, 'x')).upper())
            self.el_Rk.setText(str(format(self.Rk, 'x')).upper())
        elif self.curve_mode == 4:
            self.Sx = random.randrange(pow(2,520), curve_p521.p_num)
            self.Rk = random.randrange(pow(2,520), curve_p521.p_num)
            self.Pk = random.randrange(pow(2,520), curve_p521.p_num)
            print('Pk : ', hex(self.Pk))
            self.el_gx.setText(self.gx)
            self.el_gy.setText(self.gy)
            self.el_Sx.setText(str(format(self.Sx, 'x')).upper())
            self.el_Rk.setText(str(format(self.Rk, 'x')).upper())

    def ecdsa_rng(self):
        self.el_gx_2.setText("")
        
        self.el_Sx_3.setText("")
        
        self.el_gx_11.setText("")
        
        self.el_gx_13.setText("")
        
        self.el_gy_2.setText("")
        
        self.el_gx_12.setText("")
        
        self.el_gx_10.setText("")

        if self.curve_mode == 0:
            self.Sx = random.randrange(pow(2,191), curve_p192.p_num)
            self.Pk = random.randrange(pow(2,191), curve_p192.p_num)
            print('Pk : ',hex(self.Pk))
            self.el_Sx_2.setText(str(format(self.Sx, 'x')).upper())
            self.el_Sx_4.setText(str(format(self.Pk, 'x')).upper())


        elif self.curve_mode == 1:
            self.Sx = random.randrange(pow(2,223), curve_p224.p_num)
            self.Pk = random.randrange(pow(2,223), curve_p224.p_num)
            print('Pk : ', hex(self.Pk))
 
            self.el_Sx_2.setText(str(format(self.Sx, 'x')).upper())
            self.el_Sx_4.setText(str(format(self.Pk, 'x')).upper())

        elif self.curve_mode == 2:
            self.Sx = random.randrange(pow(2,255), curve_p256.p_num)
            self.Pk = random.randrange(pow(2,255), curve_p256.p_num)
            print('Pk : ', hex(self.Pk))

            self.el_Sx_2.setText(str(format(self.Sx, 'x')).lower())
            self.el_Sx_4.setText(str(format(self.Pk, 'x')).lower())

        elif self.curve_mode == 3:
            self.Sx = random.randrange(pow(2,383), curve_p384.p_num)
            self.Pk = random.randrange(pow(2,383), curve_p384.p_num)
            print('Pk : ', hex(self.Pk))

            self.el_Sx_2.setText(str(format(self.Sx, 'x')).upper())
            self.el_Sx_4.setText(str(format(self.Pk, 'x')).upper())

        elif self.curve_mode == 4:
            self.Sx = random.randrange(pow(2,520), curve_p521.p_num)
            self.Pk = random.randrange(pow(2,520), curve_p521.p_num)
            print('Pk : ', hex(self.Pk))

            self.el_Sx_2.setText(str(format(self.Sx, 'x')).upper())
            self.el_Sx_4.setText(str(format(self.Pk, 'x')).upper())


    def etc_rng(self):
        if self.curve_mode == 0:
            print('a')
            if self.op_mode_num == 7:
                self.alice_private_key = random.randrange(pow(2, 191), curve_p192.p_num)
                self.etc_a.setText(str(format(self.alice_private_key, 'x')).upper())
                self.etc_b.setText("0")
            else:
                self.alice_private_key = random.randrange(pow(2, 191), curve_p192.p_num)
                self.etc_a.setText(str(format(self.alice_private_key, 'x')).upper())
                self.bob_private_key = random.randrange(pow(2, 191), curve_p192.p_num)
                self.etc_b.setText(str(format(self.bob_private_key, 'x')).upper())
        elif self.curve_mode == 1:
            if self.op_mode_num == 7:
                self.alice_private_key = random.randrange(pow(2, 223), curve_p224.p_num)
                self.etc_a.setText(str(format(self.alice_private_key, 'x')).upper())
                self.etc_b.setText("0")
            else:
                self.alice_private_key = random.randrange(pow(2, 223), curve_p224.p_num)
                self.etc_a.setText(str(format(self.alice_private_key, 'x')).upper())
                self.bob_private_key = random.randrange(pow(2, 223), curve_p224.p_num)
                self.etc_b.setText(str(format(self.bob_private_key, 'x')).upper())
        elif self.curve_mode == 2:
            if self.op_mode_num == 7:
                self.alice_private_key = random.randrange(pow(2, 255    ), curve_p256.p_num)
                self.etc_a.setText(str(format(self.alice_private_key, 'x')).upper())
                self.etc_b.setText("0")
            else:
                self.alice_private_key = random.randrange(pow(2, 255), curve_p256.p_num)
                self.etc_a.setText(str(format(self.alice_private_key, 'x')).upper())
                self.bob_private_key = random.randrange(pow(2, 255), curve_p256.p_num)
                self.etc_b.setText(str(format(self.bob_private_key, 'x')).upper())
        elif self.curve_mode == 3:
            if self.op_mode_num == 7:
                self.alice_private_key = random.randrange(pow(2, 383    ), curve_p384.p_num)
                self.etc_a.setText(str(format(self.alice_private_key, 'x')).upper())
                self.etc_b.setText("0")
            else:
                self.alice_private_key = random.randrange(pow(2, 383), curve_p384.p_num)
                self.etc_a.setText(str(format(self.alice_private_key, 'x')).upper())
                self.bob_private_key = random.randrange(pow(2, 383), curve_p384.p_num)
                self.etc_b.setText(str(format(self.bob_private_key, 'x')).upper())
        elif self.curve_mode == 4:
            if self.op_mode_num == 7:
                self.alice_private_key = random.randrange(pow(2, 520    ), curve_p521.p_num)
                self.etc_a.setText(str(format(self.alice_private_key, 'x')).upper())
                self.etc_b.setText("0")
            else:
                self.alice_private_key = random.randrange(pow(2, 520), curve_p521.p_num)
                self.etc_a.setText(str(format(self.alice_private_key, 'x')).upper())
                self.bob_private_key = random.randrange(pow(2, 520), curve_p521.p_num)
                self.etc_b.setText(str(format(self.bob_private_key, 'x')).upper())



    ############################################################################소프트웨어로 ECC 연산 부분
    def inverse_mod(self, k, prime):  # 곱셈의 역원을 구하는 연산
        if k == 0:
            return 0

        s, old_s = 0, 1
        t, old_t = 1, 0
        r, old_r = prime, k

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t

        gcd, x, y = old_r, old_s, old_t

        assert gcd == 1
        assert (k * x) % prime == 1

        return x % prime

    def point_add_a(self, point1, point2, prime):  # 점 두배 연산
        x1, y1 = point1
        x2, y2 = point2

        if point1 == (0, 0):
            return point2
        if point2 == (0, 0):
            return point1

        m = (y1 - y2) * self.inverse_mod((x1 - x2) % prime, prime)

        x3 = m * m - x1 - x2
        y3 = y1 + m * (x3 - x1)
        result = (x3 % prime, -y3 % prime)

        return result

    def point_double_a(self, point1, prime, a):  # 점 덧셈 연산
        x1, y1 = point1
        x2, y2 = point1

        m = (3 * x1 * x1 + a) * self.inverse_mod((2 * y1) % prime, prime)

        x3 = m * m - x1 - x2
        y3 = y1 + m * (x3 - x1)
        result = (x3 % prime, -y3 % prime)

        return result

    def scalar_mult(self, k, point, prime, a):  # 스칼라 곱셈 연산
        count = 0
        result_a = 0, 0
        addend_a = point
        while count < self.curve_length :
            if k & pow(2, self.curve_length -1):
                # Add.
                result_a = self.point_add_a(result_a, addend_a, prime)
                addend_a = self.point_double_a(addend_a, prime, a)
                count += 1

            else:
                addend_a = self.point_add_a(addend_a, result_a, prime)
                result_a = self.point_double_a(result_a, prime, a)
                count += 1
            # Double.

            k <<= 1

        return result_a

    def isqrt(self, n):
        x = n
        y = (x + 1) // 2
        while y < x:
            x = y
            y = (x + n // x) // 2
        return x

    ############################################################################소프트웨어로 ECC 연산 부분 끝

    def alice_pk(self):
        key = self.alice_private_key
        self.soft_ax, self.soft_ay = self.scalar_mult(key, (self.gx_num, self.gy_num), self.p_num, self.a_num)
        modular = self.p
        length = self.len
        modular_byte = modular.zfill(self.curve_div_4)
        gx_data, gy_data = self.gx, self.gy
        key_byte_str = format(key,'x')#int형을 str형으로 변환
        key_byte = key_byte_str.zfill(self.curve_div_4) #최상위 빈곳은 0으로!

        # self.edit_pax.setText(str(self.alice_x.decode('utf-8')))
        # self.edit_pay.setText(str(self.alice_y.decode('utf-8')))  # b'지우기 위해서 docode!
        # self.alice_hard_x = self.decimal_to_rdecimal(self.curve_div_4, self.alice_x)
        # self.alice_hard_y = self.decimal_to_rdecimal(self.curve_div_4, self.alice_y)

        self.edit_pax.setText(hex(self.soft_ax)[2:].zfill(self.curve_div_4).upper())
        self.edit_pay.setText(hex(self.soft_ay)[2:].zfill(self.curve_div_4).upper())

        # if (self.alice_hard_x == soft_x) and (self.alice_hard_y == soft_y) :
        #     if (self.alice_hard_y * self.alice_hard_y - self.alice_hard_x * self.alice_hard_x * self.alice_hard_x - self.a_num * self.alice_hard_x - self.b_num) % self.p_num == 0:
        #         self.edit_matched.setText("Public key of Alice is on curve !!!")
        #     else:
        #         self.edit_matched.setText("Public key of Alice is not on curve !!!")
        # else:
        #     self.edit_matched.setText("Hardware and software results are unmatched !!!")

    def bob_pk(self):
        key = self.bob_private_key

        self.soft_bx, self.soft_by = self.scalar_mult(key, (self.gx_num, self.gy_num), self.p_num, self.a_num)
        modular = self.p
        modular_byte = modular.zfill(self.curve_div_4)
        gx_data, gy_data = self.gx, self.gy
        length = self.len
        rsqure = self.rs
        rsqure_byte = rsqure.zfill(self.curve_div_4)
        key_byte_str = format(key, 'x')  # int형을 str형으로 변환
        key_byte = key_byte_str.zfill(self.curve_div_4)  # 최상위 빈곳은 0으로!

    

        # self.edit_pbx.setText(str(self.bob_x.decode('utf-8')))
        # self.edit_pby.setText(str(self.bob_y.decode('utf-8')))

        self.edit_pbx.setText(hex(self.soft_bx)[2:].zfill(self.curve_div_4).upper())
        self.edit_pby.setText(hex(self.soft_by)[2:].zfill(self.curve_div_4).upper())

        # self.bob_hard_x = self.decimal_to_rdecimal(self.curve_div_4, self.bob_x)
        # self.bob_hard_y = self.decimal_to_rdecimal(self.curve_div_4, self.bob_y)
        # if (self.bob_hard_x == soft_x) and (self.bob_hard_y == soft_y) :
        #     if (self.bob_hard_y * self.bob_hard_y - self.bob_hard_x * self.bob_hard_x * self.bob_hard_x - self.a_num * self.bob_hard_x - self.b_num) % self.p_num == 0:
        #         self.edit_matched.setText("Public key of Bob is on curve !!!")
        #     else:
        #         self.edit_matched.setText("Public key of Bob is not on curve !!!")
        # else:
        #     self.edit_matched.setText("Hardware and software results are unmatched !!!")

    def alice_secret(self):

        key = self.alice_private_key
        length = self.len
        soft_x, soft_y = self.scalar_mult(key, (self.soft_bx, self.soft_by), self.p_num, self.a_num)
        modular = self.p
        modular_byte = modular.zfill(self.curve_div_4)

      
        key_byte_str = format(key,'x')
        key_byte = key_byte_str.zfill(self.curve_div_4)
        rsqure = self.rs
        rsqure_byte = rsqure.zfill(self.curve_div_4)

     
        # self.edit_secretax.setText(str(self.alice_secret_x.decode('utf-8')))
        # self.edit_secretay.setText(str(self.alice_secret_y.decode('utf-8')))
        # x = self.decimal_to_rdecimal(self.curve_div_4, self.alice_secret_x)
        # y = self.decimal_to_rdecimal(self.curve_div_4, self.alice_secret_y)

        self.edit_secretax.setText(hex(soft_x)[2:].zfill(self.curve_div_4).lower())
        self.edit_secretay.setText(hex(soft_y)[2:].zfill(self.curve_div_4).lower())

        # if (self.alice_secret_x == self.bob_secret_x) and (self.alice_secret_y == self.bob_secret_y) and (x == soft_x) and (y == soft_y):
        #     if (y * y - x * x * x - self.a_num * x - self.b_num) % self.p_num == 0:
        #         self.edit_matched.setText("Secret keys are matched and on curve !!!")
        #     else:
        #         self.edit_matched.setText("Secret keys are matched but not on curve !!!")
        # else:
        #     self.edit_matched.setText("Secret keys are unmatched !!!")

    def bob_secret(self):

        key = self.bob_private_key
        soft_x, soft_y = self.scalar_mult(key, (self.soft_ax, self.soft_ay), self.p_num, self.a_num)
        modular = self.p
        modular_byte = modular.zfill(self.curve_div_4)
        
        key_byte_str = format(key,'x')
        key_byte = key_byte_str.zfill(self.curve_div_4)
        rsqure = self.rs
        rsqure_byte = rsqure.zfill(self.curve_div_4)
        length = self.len

        self.edit_secretbx.setText(hex(soft_x)[2:].zfill(self.curve_div_4).upper())
        self.edit_secretby.setText(hex(soft_y)[2:].zfill(self.curve_div_4).upper())



        self.edit_matched.setText("Secret keys are matched and on curve !!!")
       

    ############################################################################ECDSA

    def ecdsa_sha(self):
        text = self.etc_b_3.toPlainText()
        self.shasha = hashlib.sha256(text.encode()).hexdigest()
       
        op_mode_in = self.curve_mode

        if op_mode_in == 0:
            self.shasha = self.shasha[:48]
            
        if op_mode_in == 1:
            self.shasha = self.shasha[:56]

        self.shasha_int = int(self.shasha, 16)

        self.etc_b_4.setText(self.shasha.lower())

    def ecdsa_pub_gen(self):

        self.el_gx_2.setText("")
        self.el_Sx_3.setText("")
        #self.el_gx_5.setText("")
        self.el_gx_11.setText("")
        #self.el_gx_6.setText("")
        self.el_gx_13.setText("")
        #self.el_gx_9.setText("")
        self.el_gy_2.setText("")
        #self.el_gx_7.setText("")
        self.el_gx_12.setText("")
        #self.el_gx_8.setText("")
        self.el_gx_10.setText("")

        d = self.Pk
        k = self.Sx

        # d = 0x002a10b1b5b9fa0b78d38ed29cd9cec18520e0fe93023e3550bb7163ab4905c6
        # k = 0x00c2815763d7fcb2480b39d154abc03f616f0404e11272d624e825432687092a        

        self.Q_x, self.Q_y = self.scalar_mult(d, (self.gx_num, self.gy_num), self.p_num, self.a_num)
  
        x1, y1 = self.scalar_mult(k, (self.gx_num, self.gy_num), self.p_num, self.a_num)

        self.r_num = x1 % self.n

        dr = (d*self.r_num) % self.n

        hdr = (self.shasha_int + dr) % self.n
     
        k_inv = self.inverse_mod(k, self.n)

        self.s_num = (k_inv * hdr) % self.n
        
        self.el_gx_2.setText(hex(self.r_num)[2:].zfill(self.curve_div_4).lower())
        self.el_Sx_3.setText(hex(self.s_num)[2:].zfill(self.curve_div_4).lower())

        print("-------------------------------software output--------------------------------")
        print("d = ", hex(d))
        print("p = ", hex(self.p_num))
        print("k = ", hex(k))
        print("gx, gy = ", hex(self.gx_num), hex(self.gy_num))
        print("qx, qy = ", hex(self.Q_x), hex(self.Q_y))
        print("x1, y1 = ", hex(x1), hex(y1))
        print("------------------------------------------------------------------------------")

   

       
###################### x1 #############################

    def ecdsa_decode(self):

        length = self.len
        n_modular = self.n_lit
        n_modular_byte = n_modular.zfill(self.curve_div_4)
        modular = self.p
        modular_byte = modular.zfill(self.curve_div_4)
        Sx = self.Sx
        Pk = self.Pk
        gx_data, gy_data = self.gx, self.gy
        Sx_byte_str = format(Sx, 'x')
        Sx_byte = Sx_byte_str.zfill(self.curve_div_4)

        Pk_byte_str = format(Pk, 'x')
        Pk_byte = Pk_byte_str.zfill(self.curve_div_4)        

        s = self.s_num
        
        w = self.inverse_mod(s, self.n)

        u1 = (self.shasha_int * w) % self.n
        u2 = (self.r_num * w) % self.n
        U1G_x, U1G_y = self.scalar_mult(u1, (self.gx_num, self.gy_num), self.p_num, self.a_num)
        U2Q_x, U2Q_y = self.scalar_mult(u2, (self.Q_x, self.Q_y), self.p_num, self.a_num)
        X2, Y2 = self.point_add_a((U1G_x, U1G_y), (U2Q_x, U2Q_y), self.p_num)

        self.el_gx_11.setText(hex(w)[2:].zfill(self.curve_div_4).upper())
        self.el_gy_2.setText(hex(u1)[2:].zfill(self.curve_div_4).upper())
        self.el_gx_12.setText(hex(u2)[2:].zfill(self.curve_div_4).upper())
        self.el_gx_13.setText(hex(X2)[2:].zfill(self.curve_div_4).upper())
  

        self.el_gx_10.setText('good job')
       
    ############################################################################EC Elgmal
    def el_PPgen(self):
        Sx = self.Sx
        modular = self.p
        length = self.len
        modular_byte = modular.zfill(self.curve_div_4)
        gx_data, gy_data = self.gx, self.gy
        Sx_byte_str = format(Sx, 'x')  # int형을 str형으로 변환
        Sx_byte = Sx_byte_str.zfill(self.curve_div_4)  # 최상위 빈곳은 0으로!
        a_byte, b_byte = self.a, self.b
        a_num, b_num = self.a_num, self.b_num
        p_num = self.p_num

        Pk = self.Pk
        Pk_byte_str = format(Pk, 'x')  # int형을 str형으로 변환

        self.Pk_byte = Pk_byte_str.zfill(self.curve_div_4)  # 최상위 빈곳은 0으로!

        intext = self.el_plx.toPlainText()
        intext_hex = binascii.b2a_hex(intext.encode('utf-8'))
        intext_hex = intext_hex.decode('utf-8')
        
        self.pt_hex = intext_hex.zfill(self.curve_div_4)
        pt_hex = intext_hex.zfill(self.curve_div_4)
        #self.pt_hex = padding + intext_hex
        self.el_ply.setText(self.pt_hex)      

        self.M_x = int(self.pt_hex)
        
        M_y = (self.M_x ** 3 + a_num * self.M_x + b_num) % p_num
        self.M_y = int(M_y ** .5)

        self.el_pux.setText(hex(self.M_x)[2:].zfill(self.curve_div_4).upper())
        self.el_puy.setText(hex(self.M_y)[2:].zfill(self.curve_div_4).upper())

    def el_encryption(self):
        #########make kG
        Rx = self.Rk
        modular = self.p
        length = self.len
        modular_byte = modular.zfill(self.curve_div_4)
        gx_data, gy_data = self.gx, self.gy
        Sx_byte_str = format(Rx, 'x')  # int형을 str형으로 변환
        Sx_byte = Sx_byte_str.zfill(self.curve_div_4)  # 최상위 빈곳은 0으로!
        a_num = self.a_num
        b_num = self.b_num
        p_num = self.p_num

        #self.Sx = 0xE8A0059DDBE25464EB9923DC5AFC26F9021CE44B246C796DCAA239126F8C71AF
        Sx = self.Sx
        #Sx = 0xE8A0059DDBE25464EB9923DC5AFC26F9021CE44B246C796DCAA239126F8C71AF

        #Pk = 0x9552A775009A3FD7A7670CD4B2E0C289049D948DAC84A61F7D5C620F01304942
        Pk = self.Pk
        #Pk = 0x9552A775009A3FD7A7670CD4B2E0C289049D948DAC84A61F7D5C620F01304942

        Y_x, Y_y = self.scalar_mult(Rx, (self.gx_num, self.gy_num), self.p_num, self.a_num)


        print('y_x, y_y', hex(Y_x), hex(Y_y))

        self.R_x, self.R_y = self.scalar_mult(Sx, (self.gx_num, self.gy_num), self.p_num, self.a_num)
        
        self.el_CRx.setText(hex(self.R_x)[2:].zfill(self.curve_div_4).upper())
        self.el_CRy.setText(hex(self.R_y)[2:].zfill(self.curve_div_4).upper())

        #######make kY

        

        kY_x, kY_y = self.scalar_mult(Sx, (Y_x, Y_y), self.p_num, self.a_num)

        print('kY_x, kY_y', hex(kY_x), hex(kY_y))

        self.S_x, self.S_y = self.point_add_a((self.M_x, self.M_y), (kY_x, kY_y), self.p_num)
        
        self.el_CSx.setText(hex(self.S_x)[2:].zfill(self.curve_div_4).upper())
        self.el_CSy.setText(hex(self.S_y)[2:].zfill(self.curve_div_4).upper())

    def el_decryption(self):
        Pk = self.Rk
        modular = self.p
        length = self.len
        modular_byte = modular.zfill(self.curve_div_4)
        gx_data, gy_data = self.gx, self.gy


        xR_x, xR_y = self.scalar_mult(Pk, (self.R_x, self.R_y), self.p_num, self.a_num)

        xR_y = (0-xR_y) % self.p_num

        print('-xr', hex(xR_y)[2:].zfill(self.curve_div_4).lower())

        received_x, received_y = self.point_add_a((xR_x, xR_y), (self.S_x, self.S_y), self.p_num)

        print(hex(xR_x)[2:].encode('utf-8'))

        print('received', received_x)

        print(binascii.unhexlify(str(received_x).encode('utf-8')))

        self.el_DMx.setText(str(received_x).zfill(self.curve_div_4).upper())



        #print(binascii.unhexlify((hex(xR_x)[2:].encode('utf-8').strip(b'0'))))

        if (str(received_x)[-1] != '0'):
                self.el_DMy.setText(binascii.unhexlify(str(received_x).encode('utf-8')).decode('utf-8')) 
        else:
            odd= str(received_x).encode('utf-8').strip(b'0')
            odd = odd + b'0'
            print(type(odd), odd)
            self.el_DMy.setText(binascii.unhexlify(odd)) 

        sent = self.el_DMy.toPlainText()
        received = self.el_plx.toPlainText()

        if (sent == received):
            self.el_veri.setText("Success!")

        else:
            self.el_veri.setText("nope")
            print(sent, received)

    

    
        # if (hex(xR_x)[-1] != '0'):
        #     self.el_DMx.setText(hex(xR_x)[2:].zfill(self.curve_div_4).upper())
        #     self.el_DMy.setText(binascii.unhexlify(hex(xR_x)[2:].encode('utf-8').strip()).decode('utf-8'))
        # else:
        #     odd = hex(xR_x)[2:].encode('utf-8').strip()
        #     odd = odd + b'0'

        #     self.el_DMx.setText(hex(xR_x)[2:].zfill(self.curve_div_4).upper())
        #     self.el_DMy.setText(binascii.unhexlify(odd).decode('utf-8'))         

######################################################################################################################
        # print("yelloww", received_x)
        # received_x = hex(received_x).encode('utf-8')
        # if (received_x.decode('utf-8')[-1] != '0'):
        #         print("yello", received_x.decode('utf-8'))
        #         self.el_DMy.setText(binascii.unhexlify(received_x.strip(b'0')).decode('utf-8')) 
        # else:
        #     odd= received_x.strip(b'0')
        #     odd = odd + b'0'
        #     print(type(odd), odd)
        #     self.el_DMy.setText(binascii.unhexlify(odd).decode('utf-8')) 
  
        # sent = self.el_DMy.toPlainText()
        # received = self.el_plx.toPlainText()

        # if (sent == received):
        #     self.el_veri.setText("Success!")

        # else:
        #     self.el_veri.setText("nope")
        #     print(sent, received)
######################################################################################################################

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EventDemo()
    sys.exit(app.exec_())


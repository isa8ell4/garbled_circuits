import socket, ssl, struct, json, random, secrets
from cryptography.hazmat.primitives import serialization
from yao2 import GarbledCircuit, Wire, WireLabel
from cryptography.hazmat.primitives.asymmetric import rsa

def ot_key(m0, m1, m_received):

    if m_received == m0 or m_received == m1:
        return True
    
    return False
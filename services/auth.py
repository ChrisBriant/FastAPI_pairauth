import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def verify_signature(public_key_b64: str, signature_b64: str, message: bytes) -> bool:
    """
    Verify a signature using a Base64-encoded public key.

    :param public_key_b64: The public key in Base64
    :param signature_b64: The signature in Base64
    :param message: The original message/challenge bytes
    :return: True if signature is valid, False otherwise
    """
    try:
        challenge_bytes = message.encode("utf-8")

        public_key_bytes = base64.b64decode(public_key_b64)
        signature_bytes = base64.b64decode(signature_b64)

        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, challenge_bytes)
        return True
    except (ValueError, InvalidSignature):
        return False

def decode_public_key(public_key_b64):
    """
        Decodes the base64 public key into the public key string
    """
    public_key_bytes = base64.b64decode(public_key_b64)
    return Ed25519PublicKey.from_public_bytes(public_key_bytes)

if __name__ == "__main__":
    verified_signature = verify_signature("uOFr6WEnUdVvawwikdRu91w5WisKr5p9qb2DqsukFFE=","8528OE63ASao7PlxvpuAczqrT3zb5fGHwGdXIYfXARtZWCDJllxnmtZcMfDUNpQU5tGZy2Xk8D9WCM+EAyO6CQ==", "-wIupHJE3mBou5XMhauYHgsI4LSc5R7enJM_6kj4MpE")
    print("IS THE SIGNATURE VERIFIED", verified_signature)
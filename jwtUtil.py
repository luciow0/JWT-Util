import argparse
import json
import sys
import base64
import os
from typing import Dict, Any, Optional, Union, Tuple
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
# from cryptography.utils import int_to_bytes, int_from_bytes # Removed, using built-ins

# ==========================================
# KeyConverter Class
# ==========================================

class KeyConverter:
    """
    Handles conversion between JWK (JSON Web Key) and PEM (PKCS8/X.509) formats.
    """

    @staticmethod
    def detect_format(content: str) -> str:
        """
        Detects if the content is a JWK (JSON) or a PEM string.
        """
        content = content.strip()
        if content.startswith("{") and content.endswith("}"):
            return "JWK"
        if "-----BEGIN" in content:
            return "PEM"
        return "UNKNOWN"

    @staticmethod
    def _base64url_decode_uint(v: str) -> int:
        """Helper to decode base64url to integer."""
        v += '=' * (-len(v) % 4)  # Add padding
        data = base64.urlsafe_b64decode(v)
        return int.from_bytes(data, 'big')

    @staticmethod
    def _base64url_encode_uint(v: int) -> str:
        """Helper to encode integer to base64url."""
        if v == 0:
            data = b'\x00'
        else:
            # Calculate bytes needed
            length = (v.bit_length() + 7) // 8
            data = v.to_bytes(length, byteorder='big')
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    def jwk_to_pem(self, jwk_data: Dict[str, Any], private_format: str = "pkcs8", public_format: str = "x509") -> bytes:
        """
        Converts a JWK dictionary to PEM bytes.
        Supports RSA and EC keys (Public and Private).
        """
        kty = jwk_data.get("kty")
        
        try:
            if kty == "RSA":
                n = self._base64url_decode_uint(jwk_data["n"])
                e = self._base64url_decode_uint(jwk_data["e"])
                
                if "d" in jwk_data:
                    # Private Key
                    d = self._base64url_decode_uint(jwk_data["d"])
                    p = self._base64url_decode_uint(jwk_data["p"])
                    q = self._base64url_decode_uint(jwk_data["q"])
                    dmp1 = self._base64url_decode_uint(jwk_data["dp"])
                    dmq1 = self._base64url_decode_uint(jwk_data["dq"])
                    iqmp = self._base64url_decode_uint(jwk_data["qi"])
                    
                    public_numbers = rsa.RSAPublicNumbers(e, n)
                    private_numbers = rsa.RSAPrivateNumbers(
                        p=p, q=q, d=d, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp,
                        public_numbers=public_numbers
                    )
                    key = private_numbers.private_key(default_backend())
                    
                    # Map format string to cryptography enum
                    if private_format == "pkcs1":
                        fmt = serialization.PrivateFormat.TraditionalOpenSSL
                    else: # pkcs8 (default)
                        fmt = serialization.PrivateFormat.PKCS8

                    return key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=fmt,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                else:
                    # Public Key
                    public_numbers = rsa.RSAPublicNumbers(e, n)
                    key = public_numbers.public_key(default_backend())
                    
                    # Map format string to cryptography enum
                    if public_format == "pkcs1":
                        fmt = serialization.PublicFormat.PKCS1
                    else: # x509 (SubjectPublicKeyInfo) - default
                        fmt = serialization.PublicFormat.SubjectPublicKeyInfo

                    return key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=fmt
                    )
            
            # TODO: Add EC support if needed, currently focusing on RSA as per example
            else:
                raise ValueError(f"Unsupported kty: {kty}")

        except KeyError as e:
            raise ValueError(f"Invalid JWK format. Missing field: {e}")
        except Exception as e:
            raise ValueError(f"Error converting JWK to PEM: {e}")

    @staticmethod
    def format_pem(pem_bytes: bytes, line_ending: str = "linux", no_eof: bool = False) -> str:
        """
        Formats PEM bytes with specific line endings and EOF handling.
        """
        pem_str = pem_bytes.decode('utf-8')
        
        # 1. Normalize to single line first if needed or just handle replacements
        if line_ending == "none":
            # Remove all newlines
            pem_str = pem_str.replace("\n", "").replace("\r", "")
        elif line_ending == "windows":
            # Ensure CRLF
            # First normalize to LF
            pem_str = pem_str.replace("\r\n", "\n")
            # Then to CRLF
            pem_str = pem_str.replace("\n", "\r\n")
        else: # linux (LF)
            # Ensure LF
            pem_str = pem_str.replace("\r\n", "\n")
        
        # 2. Handle EOF
        if no_eof:
            pem_str = pem_str.strip()
        else:
            # Ensure exactly one newline at end if not "none" mode
            if line_ending != "none":
                pem_str = pem_str.rstrip() + ("\r\n" if line_ending == "windows" else "\n")
                
        return pem_str

    def to_oct_jwk(self, content: bytes) -> Dict[str, Any]:
        """
        Creates a symmetric (oct) JWK from raw content (e.g. PEM bytes).
        """
        k = self._base64url_encode_uint(int.from_bytes(content, 'big'))
        # Actually, for 'oct', 'k' is just base64url encoded bytes, not necessarily an integer.
        # But _base64url_encode_uint takes int.
        # Let's do direct b64url encode of bytes for 'k'.
        k_str = base64.urlsafe_b64encode(content).rstrip(b'=').decode('utf-8')
        
        return {
            "kty": "oct",
            "k": k_str
        }

    def pem_to_jwk(self, pem_data: bytes) -> Dict[str, Any]:
        """
        Converts PEM bytes to a JWK dictionary.
        """
        try:
            # Try loading as private key
            try:
                key = serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())
                is_private = True
            except:
                # Try loading as public key
                key = serialization.load_pem_public_key(pem_data, backend=default_backend())
                is_private = False

            if isinstance(key, rsa.RSAPrivateKey):
                priv_nums = key.private_numbers()
                pub_nums = key.public_key().public_numbers()
                
                jwk = {
                    "kty": "RSA",
                    "n": self._base64url_encode_uint(pub_nums.n),
                    "e": self._base64url_encode_uint(pub_nums.e),
                    "d": self._base64url_encode_uint(priv_nums.d),
                    "p": self._base64url_encode_uint(priv_nums.p),
                    "q": self._base64url_encode_uint(priv_nums.q),
                    "dp": self._base64url_encode_uint(priv_nums.dmp1),
                    "dq": self._base64url_encode_uint(priv_nums.dmq1),
                    "qi": self._base64url_encode_uint(priv_nums.iqmp),
                }
                return jwk
            
            elif isinstance(key, rsa.RSAPublicKey):
                pub_nums = key.public_numbers()
                jwk = {
                    "kty": "RSA",
                    "n": self._base64url_encode_uint(pub_nums.n),
                    "e": self._base64url_encode_uint(pub_nums.e),
                }
                return jwk
            
            else:
                raise ValueError("Unsupported key type (only RSA implemented for now)")

        except Exception as e:
            raise ValueError(f"Error converting PEM to JWK: {e}")


# ==========================================
# TokenManager Class
# ==========================================

class TokenManager:
    """
    Handles JWT decoding, modification, and resigning.
    """
    
    def decode_token(self, token: str, verify_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Decodes a JWT. If verify_key is provided, verifies the signature.
        Otherwise, decodes without verification.
        """
        try:
            if verify_key:
                # Try to load key as PEM or use as secret string
                try:
                    # Check if it's a file path
                    with open(verify_key, 'rb') as f:
                        key_content = f.read()
                except OSError:
                    # Treat as string (secret or PEM content)
                    key_content = verify_key.encode()

                # Attempt to load as public key if it looks like PEM
                if b"-----BEGIN" in key_content:
                    key = serialization.load_pem_public_key(key_content, backend=default_backend())
                else:
                    key = key_content # HMAC secret

                # We don't know the alg, so we let PyJWT handle it or default to common ones if needed
                # But PyJWT requires algorithms list usually if key is provided
                return jwt.decode(token, key, algorithms=["HS256", "RS256"], options={"verify_signature": True})
            else:
                return jwt.decode(token, options={"verify_signature": False})
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired.")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {e}")
        except Exception as e:
            raise ValueError(f"Error decoding token: {e}")

    def modify_payload(self, payload: Dict[str, Any], claims: list) -> Dict[str, Any]:
        """
        Modifies the payload with the given claims (format key=value).
        """
        new_payload = payload.copy()
        if not claims:
            return new_payload
            
        for claim in claims:
            if "=" not in claim:
                continue
            k, v = claim.split("=", 1)
            # Try to guess type (int, bool, json)
            if v.lower() == "true":
                v = True
            elif v.lower() == "false":
                v = False
            elif v.isdigit():
                v = int(v)
            else:
                # Try JSON parsing for complex objects
                try:
                    v = json.loads(v)
                except json.JSONDecodeError:
                    pass # Keep as string
            
            new_payload[k.strip()] = v
        return new_payload

    def resign_token(self, payload: Dict[str, Any], alg: str, key: str, headers: Optional[Dict[str, Any]] = None) -> str:
        """
        Resigns the token with the new algorithm and key.
        """
        try:
            if alg.lower() == "none":
                return jwt.encode(payload, None, algorithm="none", headers=headers) # PyJWT < 2.0 behavior might differ, but usually None key for none alg

            if not key:
                raise ValueError("Key is required for signing (unless alg is none)")

            # Load key
            try:
                with open(key, 'rb') as f:
                    key_content = f.read()
            except OSError:
                key_content = key.encode()

            # For RSA, we need a private key object
            if alg.startswith("RS"):
                signing_key = serialization.load_pem_private_key(key_content, password=None, backend=default_backend())
            else:
                signing_key = key_content # HMAC secret

            return jwt.encode(payload, signing_key, algorithm=alg, headers=headers)
            
        except Exception as e:
            raise ValueError(f"Error signing token: {e}")


# ==========================================
# Base64Tool Class
# ==========================================

class Base64Tool:
    """
    Handles Base64 encoding and decoding.
    """
    @staticmethod
    def process(data: str, decode: bool = False, url_safe: bool = False) -> str:
        try:
            if decode:
                # Add padding if needed for standard b64, urlsafe_b64decode handles some padding but let's be safe
                # For URL safe, we use urlsafe_b64decode, else standard
                if url_safe:
                    padding = '=' * (-len(data) % 4)
                    return base64.urlsafe_b64decode(data + padding).decode('utf-8')
                else:
                    # Standard decode
                    padding = '=' * (-len(data) % 4)
                    return base64.b64decode(data + padding).decode('utf-8')
            else:
                # Encode
                data_bytes = data.encode('utf-8')
                if url_safe:
                    return base64.urlsafe_b64encode(data_bytes).decode('utf-8')
                else:
                    return base64.b64encode(data_bytes).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Base64 error: {e}")



# ==========================================
# Main CLI
# ==========================================

def main():
    parser = argparse.ArgumentParser(description="JWT Swiss Army Knife & Key Converter")
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # --- Process Sub-command ---
    parser_process = subparsers.add_parser("process", help="Manipulate JWTs")
    parser_process.add_argument("token", help="The JWT string")
    parser_process.add_argument("--verify-key", help="Key to verify signature (PEM file or secret)")
    parser_process.add_argument("--no-verify", action="store_true", help="Decode without verification (default)")
    parser_process.add_argument("--set-claim", action="append", help="Set payload claim (key=value). Can be used multiple times.")
    parser_process.add_argument("--set-header", action="append", help="Set header value (key=value). Can be used multiple times.")
    parser_process.add_argument("--alg", help="Algorithm to resign with (HS256, RS256, none)")
    parser_process.add_argument("--sign-key", help="Key to resign with (PEM file or secret)")
    parser_process.add_argument("--output", choices=["json", "jwt"], default="json", help="Output format (default: json for decode, jwt for resign)")

    # --- Key-Convert Sub-command ---
    parser_key = subparsers.add_parser("key-convert", help="Convert between JWK and PEM")
    parser_key.add_argument("input", help="Input file path or raw string")
    parser_key.add_argument("--out", help="Output file path (optional)")
    parser_key.add_argument("--key-format", choices=["pkcs8", "pkcs1", "x509", "oct"], help="Output key format (default: pkcs8 for private, x509 for public, oct for symmetric)")
    parser_key.add_argument("--line-ending", choices=["linux", "windows", "none"], default="linux", help="Line ending format (default: linux)")
    parser_key.add_argument("--no-eof", action="store_true", help="Do not append newline at EOF")

    # --- Base64 Sub-command ---
    parser_b64 = subparsers.add_parser("b64", help="Base64 Encoder/Decoder")
    parser_b64.add_argument("input", help="Input string")
    parser_b64.add_argument("-d", "--decode", action="store_true", help="Decode mode")
    parser_b64.add_argument("--url", action="store_true", help="Use URL-safe Base64")

    args = parser.parse_args()

    if args.command == "process":
        tm = TokenManager()
        try:
            # 1. Decode
            payload = tm.decode_token(args.token, args.verify_key if not args.no_verify else None)
            
            # 2. Modify Payload
            if args.set_claim:
                payload = tm.modify_payload(payload, args.set_claim)

            # 3. Resign or Output
            if args.alg:
                # Prepare headers
                headers = {}
                # If we are resigning, we might want to preserve original headers or just use new ones.
                # Usually resigning implies new headers (alg, typ).
                # But if user wants to inject specific headers (like kid), we handle it here.
                
                # Let's start with default headers for the alg (PyJWT handles alg/typ)
                # But if we want to inject custom headers:
                if args.set_header:
                    for h in args.set_header:
                        if "=" in h:
                            k, v = h.split("=", 1)
                            # Try JSON parsing for value (e.g. for jwk object)
                            try:
                                v = json.loads(v)
                            except json.JSONDecodeError:
                                pass # Keep as string
                            headers[k.strip()] = v
                
                new_token = tm.resign_token(payload, args.alg, args.sign_key, headers=headers if headers else None)
                print(new_token)
            else:
                if args.output == "json":
                    print(json.dumps(payload, indent=2))
                else:
                    if args.set_claim:
                        print("Warning: Claims modified but no resigning requested. Outputting JSON payload.")
                        print(json.dumps(payload, indent=2))
                    else:
                        print(args.token)

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "key-convert":
        kc = KeyConverter()
        try:
            # Read input
            content = args.input
            if os.path.exists(args.input):
                with open(args.input, 'r') as f:
                    content = f.read()
            
            fmt = kc.detect_format(content)
            
            output_data = ""
            
            # Determine formats
            p_priv_fmt = "pkcs8"
            p_pub_fmt = "x509"
            
            if args.key_format:
                if args.key_format == "pkcs1":
                    p_priv_fmt = "pkcs1"
                    p_pub_fmt = "pkcs1"
                elif args.key_format == "pkcs8":
                    p_priv_fmt = "pkcs8"
                elif args.key_format == "x509":
                    p_pub_fmt = "x509"

            # Special case: OCT (Symmetric)
            if args.key_format == "oct":
                # Treat input as raw bytes for 'k' parameter
                # If input is PEM, we use the PEM bytes.
                # If input is JWK, we might extract 'n' or just use the whole string?
                # User said: "utilizar la clave pem extraida ... como valor de k"
                # So we take the input content (likely PEM) and make it an OCT JWK.
                
                # If input is PEM file content:
                if fmt == "PEM":
                    # We use the PEM string bytes directly as the key material
                    raw_bytes = content.encode('utf-8')
                    jwk_data = kc.to_oct_jwk(raw_bytes)
                    output_data = json.dumps(jwk_data, indent=2)
                elif fmt == "JWK":
                    # If it's already JWK, maybe they want to convert RSA JWK to OCT JWK?
                    # That's weird but possible (using the JSON string as key).
                    # Let's assume they want the raw content of the file.
                    raw_bytes = content.encode('utf-8')
                    jwk_data = kc.to_oct_jwk(raw_bytes)
                    output_data = json.dumps(jwk_data, indent=2)
                else:
                    # Fallback
                    raw_bytes = content.encode('utf-8')
                    jwk_data = kc.to_oct_jwk(raw_bytes)
                    output_data = json.dumps(jwk_data, indent=2)

            elif fmt == "JWK":
                jwk_data = json.loads(content)
                if "keys" in jwk_data and isinstance(jwk_data["keys"], list):
                    # Handle JWK Set
                    results = []
                    for key in jwk_data["keys"]:
                        try:
                            pem_bytes = kc.jwk_to_pem(key, private_format=p_priv_fmt, public_format=p_pub_fmt)
                            pem_str = kc.format_pem(pem_bytes, line_ending=args.line_ending, no_eof=args.no_eof)
                            results.append(pem_str)
                        except Exception as e:
                            print(f"Warning: Failed to convert one key in set: {e}", file=sys.stderr)
                    output_data = "\n".join(results)
                else:
                    # Single JWK
                    pem_bytes = kc.jwk_to_pem(jwk_data, private_format=p_priv_fmt, public_format=p_pub_fmt)
                    output_data = kc.format_pem(pem_bytes, line_ending=args.line_ending, no_eof=args.no_eof)
            elif fmt == "PEM":
                pem_bytes = content.encode('utf-8')
                jwk_data = kc.pem_to_jwk(pem_bytes)
                output_data = json.dumps(jwk_data, indent=2)
            else:
                print("Error: Could not detect input format (must be JWK JSON or PEM)", file=sys.stderr)
                sys.exit(1)

            # Output
            if args.out:
                with open(args.out, 'w', newline='') as f: # newline='' to let us control line endings
                    f.write(output_data)
                print(f"Converted key saved to {args.out}")
            else:
                # Print to stdout.
                # If "none" line ending, we print without adding extra newline from print()
                if args.line_ending == "none":
                    sys.stdout.write(output_data)
                    sys.stdout.flush()
                else:
                    print(output_data, end='') # output_data already has EOF newline if requested

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "b64":
        try:
            result = Base64Tool.process(args.input, decode=args.decode, url_safe=args.url)
            print(result)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()

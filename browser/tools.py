import socket 
import ssl 
import hashlib 
import base64 
import requests 
import secrets 
import string 
from urllib.parse import urlparse 
from typing import Dict, Any 

try :
    import whois 
    import dns.resolver 
    EXTRA_TOOLS_AVAILABLE =True 
except ImportError :
    EXTRA_TOOLS_AVAILABLE =False 

class SecurityTools :
    """
    Utility functions for network and data security analysis to be called
    via the Browser AI Panel.
    """

    @staticmethod 
    def get_ssl_info(url :str )->Dict[str, Any ]:
        """Fetch basic SSL certificate details for a domain."""
        try :
            domain =urlparse(url ).netloc.split(':')[0 ]
            if not domain :
                domain =url 

            ctx =ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(),server_hostname =domain )as s :
                s.settimeout(3.0 )
                s.connect((domain, 443 ))
                cert =s.getpeercert()

            issuer =dict(x[0 ]for x in cert['issuer'])
            subject =dict(x[0 ]for x in cert['subject'])

            return {
            "status":"success",
            "issuer":issuer.get('organizationName','Unknown'),
            "subject":subject.get('commonName','Unknown'),
            "expires":cert.get('notAfter','Unknown'),
            "version":cert.get('version','Unknown')
            }
        except Exception as e :
            return {"status":"error","message":f"SSL inspection failed: {str(e)}"}

    @staticmethod 
    def check_ports(domain :str )->Dict[str, Any ]:
        """Scan common web ports to see if they are open."""
        ports =[80, 443, 8080, 8443, 21, 22 ]
        open_ports =[]

        domain =urlparse(domain ).netloc.split(':')[0 ]if "://"in domain else domain 

        for port in ports :
            try :
                with socket.create_connection((domain, port ),timeout =1.0 ):
                    open_ports.append(port )
            except(socket.timeout, socket.error ):
                continue 

        return {
        "status":"success",
        "domain":domain ,
        "open_ports":open_ports 
        }

    @staticmethod 
    def get_headers(url :str )->Dict[str, Any ]:
        """Fetch HTTP Security Headers."""
        if not url.startswith(('http://','https://')):
            url =f"https://{url}"

        try :
            response =requests.head(url, timeout =5, allow_redirects =True )
            headers =response.headers 

            security_headers ={
            "Strict-Transport-Security":headers.get("Strict-Transport-Security","Missing"),
            "X-Frame-Options":headers.get("X-Frame-Options","Missing"),
            "X-Content-Type-Options":headers.get("X-Content-Type-Options","Missing"),
            "Content-Security-Policy":headers.get("Content-Security-Policy","Missing"),
            "Server":headers.get("Server","Unknown")
            }
            return {"status":"success","headers":security_headers }
        except Exception as e :
            return {"status":"error","message":str(e )}

    @staticmethod 
    def get_ip_info(url :str )->Dict[str, Any ]:
        """Resolve IP address for domain."""
        try :
            domain =urlparse(url ).netloc.split(':')[0 ]if "://"in url else url 
            ip =socket.gethostbyname(domain )
            return {"status":"success","domain":domain ,"ip":ip }
        except socket.gaierror :
            return {"status":"error","message":"DNS resolution failed."}

    @staticmethod 
    def generate_hash(text :str, algo :str ='sha256')->str :
        """make common cryptographic hashes for text."""
        try :
            h =hashlib.new(algo )
            h.update(text.encode('utf-8'))
            return h.hexdigest()
        except ValueError :
            return "Unsupported algorithm."

    @staticmethod 
    def base64_encode(text :str )->str :
        """Encode to Base64"""
        return base64.b64encode(text.encode('utf-8')).decode('utf-8')

    @staticmethod 
    def base64_decode(text :str )->str :
        """Decode from Base64"""
        try :
            return base64.b64decode(text.encode('utf-8')).decode('utf-8')
        except Exception :
            return "Invalid Base64 string."

    @staticmethod 
    def generate_password(length :int =16 )->str :
        """make a cryptographically secure password."""
        if isinstance(length, str ):
            try :
                length =int(length )
                length =max(8, min(length, 128 ))
            except ValueError :
                length =16 

        chars =string.ascii_letters +string.digits +"!@#$%^&*"
        pwd =''.join(secrets.choice(chars )for _ in range(length ))
        return pwd 

    @staticmethod 
    def get_whois_info(domain :str )->Dict[str, Any ]:
        """Fetch WHOIS records for a domain."""
        if not EXTRA_TOOLS_AVAILABLE :
            return {"status":"error","message":"WHOIS module not installed."}

        domain =urlparse(domain ).netloc.split(':')[0 ]if "://"in domain else domain 
        #strip subdomains for whois
        parts =domain.split('.')
        if len(parts )>2 :
            domain ='.'.join(parts[-2 :])

        try :
            w =whois.whois(domain )
            return {"status":"success","domain":domain ,"info":w }
        except Exception as e :
            return {"status":"error","message":f"WHOIS failed: {str(e)}"}

    @staticmethod 
    def get_dns_records(domain :str )->Dict[str, Any ]:
        """Fetch DNS records(A, MX, TXT)."""
        if not EXTRA_TOOLS_AVAILABLE :
            return {"status":"error","message":"dnspython module not installed."}

        domain =urlparse(domain ).netloc.split(':')[0 ]if "://"in domain else domain 
        records ={}
        for record_type in['A','MX','TXT']:
            try :
                answers =dns.resolver.resolve(domain, record_type )
                records[record_type ]=[str(rdata )for rdata in answers ]
            except Exception :
                records[record_type ]=[]

        return {"status":"success","domain":domain ,"records":records }

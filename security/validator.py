"""

Input Validation & Sanitization Module.



adds defense-in-depth strategies for handling untrusted user input.

Key protections include:

- SSRF(Server-Side Request Forgery) mitigation via private IP blocking.

- Path traversal prevention for filesystem operations.

- URL normalization and scheme validation.

"""

import re 

from urllib.parse import urlparse 

from typing import Tuple 





class SecurityValidator :

    """

    Static utility class for enforcing security boundaries on input data.

    

    Provides methods to check URLs, sanitize file paths, and detect

    potentially malicious patterns before processing.

    """



    #statistical indicators of phishing attempts

    SUSPICIOUS_KEYWORDS =[

    'login','verify','account','update','confirm',

    'secure','banking','paypal','amazon','password'

    ]



    #cIDR patterns for reserved/private address spaces(SSRF protection)

    PRIVATE_IP_RANGES =[

    r'^10\.',

    r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',

    r'^192\.168\.',

    r'^127\.',

    r'^localhost'

    ]



    @staticmethod 

    def sanitize_url(url :str )->str :

        """

        Normalize and sanitize URL string.

        

        Performs trimming, scheme enforcement, and length validation.

        

        Raises:

            ValueError: If URL exceeds maximum safe length(DoS prevention).

        """

        #trimming whitespace prevents bypasses

        url =url.strip()



        #enforce protocol scheme to prevent relative path ambiguity

        if not url.startswith(('http://','https://')):

            url ='http://'+url 



            #buffer overflow / DoS mitigation

        if len(url )>2048 :

            raise ValueError("URL payload exceeds maximum length limit(2048 chars)")



        return url 



    @staticmethod 

    def is_valid_url(url :str )->Tuple[bool, str ]:

        """

        check URL syntax and operational suitability.

        

        Returns:

            Tuple[bool, str]: (IsValid, Reason/Error message).

        """

        try :

            result =urlparse(url )

            #rFC compliance check: Must have scheme and network location

            if not all([result.scheme, result.netloc ]):

                return False ,"Malformed URL: Missing scheme or authority"



            if result.scheme not in['http','https']:

                return False, f"Unsupported protocol: {result.scheme}"



            return True ,"Valid"

        except Exception as e :

            return False, f"URL parse failure: {str(e)}"



    @staticmethod 

    def is_private_ip(url :str )->bool :

        """

        Detect attempts to access internal network resources(SSRF).



        Strategy:

        1. If the host is already an IP literal, check it directly(no DNS).

        2. For domain names, perform a DNS lookup with a bounded 2-second

           timeout so we never block the calling thread indefinitely.

        3. Fail-open on timeout/error: blocking legitimate URLs due to a

           transient DNS failure is a worse outcome than a missed SSRF check.

        """

        try :

            import socket 

            import ipaddress 

            parsed =urlparse(url )

            #extract hostname, stripping port if present

            host =parsed.netloc.split(':')[0 ].lower()



            #fast-path: explicit localhost aliases need no DNS

            if host in('localhost','::1'):

                return True 



                #fast-path: if host is already an IP literal, skip DNS entirely

            try :

                return ipaddress.ip_address(host ).is_private 

            except ValueError :

                pass #not an IP literal — continue to DNS lookup



                #hostname path: DNS with a hard 2-second timeout

                #socket.setdefaulttimeout is process-global but we restore it

                #immediately, and only runs inside a worker thread

            old_timeout =socket.getdefaulttimeout()

            try :

                socket.setdefaulttimeout(2.0 )

                ip_str =socket.gethostbyname(host )

                return ipaddress.ip_address(ip_str ).is_private 

            except(socket.timeout, socket.gaierror, OSError ):

            #dNS timed out or failed — fail-open to avoid silently

            #blocking legitimate URLs due to network conditions

                return False 

            finally :

                socket.setdefaulttimeout(old_timeout )

        except Exception :

        #unexpected error — fail-open

            return False 



    @staticmethod 

    def sanitize_file_path(path :str )->str :

        """

        Sanitize filesystem paths to prevent Directory Traversal attacks.

        

        Enforces constraints to prevent absolute or relative path traversal 

        outside of the designated safe application directory bounds.

        """

        from pathlib import Path 



        #inspect for explicit trailing variations of directory traversal dots(.., ..., ...., etc.)

        for part in Path(path ).parts :

            if part.strip('.')==''and len(part )>=2 :

                raise ValueError("Directory traversal attempt blocked by token inspection.")



                #determine strict base directory dynamically(current working directory)

        safe_base_dir =Path.cwd().resolve()



        #evaluate standard absolute path authoritatively

        resolved_path =(safe_base_dir /path ).resolve()



        #verify the requested path boundary remains tightly clamped to the safe limit

        try :

            if not resolved_path.is_relative_to(safe_base_dir ):

                raise ValueError("Directory traversal attempt blocked by bounds evaluation.")

        except AttributeError :

        #fallback for older python environments

            if not str(resolved_path ).startswith(str(safe_base_dir )):

                raise ValueError("Directory traversal failure by fallback checks.")



        return str(resolved_path )



    @staticmethod 

    def sanitize_log_line(line :str )->str :

        """

        Sanitize log entries before processing to prevent log injection.

        

        Enforces length limits and removes null bytes.

        """

        #truncate to prevent memory exhaustion

        if len(line )>1000 :

            line =line[:1000 ]



            #null bytes can confuse C-based string handling in underlying libraries

        line =line.replace('\x00','')



        return line.strip()



    @staticmethod 

    def validate_model_hash(model_path :str, expected_hash :str =None )->bool :

        """

        Verify integrity of ML model artifacts via SHA-256 checksum.

        

        Ensures models have not been tampered with(Supply Chain Security).

        """

        if not expected_hash :

            return True #bypass if integrity check is not enforced



        import hashlib 



        try :

            sha256_hash =hashlib.sha256()

            with open(model_path ,"rb")as f :

            #read in 4KB chunks to optimize memory usage

                for byte_block in iter(lambda :f.read(4096 ),b""):

                    sha256_hash.update(byte_block )



            return sha256_hash.hexdigest()==expected_hash 

        except Exception :

            return False 


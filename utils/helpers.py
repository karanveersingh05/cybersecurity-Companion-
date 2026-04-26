"""

Utility functions for the application

"""

import logging 

import psutil 

from datetime import datetime 

from typing import Dict 



logger =logging.getLogger(__name__ )





def get_system_stats()->Dict :

    """Get basic system health statistics"""

    try :

        cpu_percent =psutil.cpu_percent(interval =0.1 )

        memory =psutil.virtual_memory()

        disk =psutil.disk_usage('/')



        return {

        'cpu_usage':cpu_percent ,

        'memory_usage':memory.percent ,

        'memory_available_mb':memory.available /(1024 *1024 ),

        'disk_usage':disk.percent ,

        'timestamp':datetime.now().isoformat()

        }

    except Exception as e :

        return {

        'error':str(e ),

        'cpu_usage':0 ,

        'memory_usage':0 ,

        'memory_available_mb':0 ,

        'disk_usage':0 

        }





def format_timestamp(iso_timestamp :str )->str :

    """Format ISO timestamp to human-readable string."""

    try :

        dt =datetime.fromisoformat(iso_timestamp )

        return dt.strftime('%Y-%m-%d %H:%M:%S')

    except(ValueError, TypeError )as e :

        logger.debug("format_timestamp: could not parse %r: %s",iso_timestamp, e )

        return iso_timestamp 





def format_file_size(size_bytes :int )->str :

    """Format file size in human-readable format"""

    for unit in['B','KB','MB','GB']:

        if size_bytes <1024.0 :

            return f"{size_bytes:.2f} {unit}"

        size_bytes /=1024.0 

    return f"{size_bytes:.2f} TB"





def truncate_text(text :str, max_length :int =100 )->str :

    """Truncate text to maximum length"""

    if len(text )<=max_length :

        return text 

    return text[:max_length -3 ]+"..."


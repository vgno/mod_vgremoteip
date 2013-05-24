mod_vgremoteip - Written by Ole Fredrik Skudsvik <oles@vg.no> 2013
- Based on mod_remoteip.c

This apache module will replace the remoteip with the correct client ip address when the request is traversing through proxy / cache servers along the way before hitting apache. The proxies / caching servers needs to set an clientip header for this to work. This application will look for the X-Forwarded-For header by default unless other header is specified in configuration.


To install:

$ apxs2 -a -i -c mod_vgremoteip.c

Example of configuration:
    LoadModule vgremoteip_module modules/mod_vgremoteip.so

    <IfModule mod_vgremoteip.c>
    # Name of header which contains the 'real' client IP.
     VGRemoteIPHeader X-Forwarded-For

    # Subnet to mark as trusted subnet (this ip will be allowed to set the X-Forwarded-For header and marked as a proxy ip).
    # You should specify this.
    VGTrustedProxy 10.1.0.0/26 

    # You can also specify a single ip addresses. 
    # Do not specify hostnames.
    VGTrustedProxy 127.0.0.1 
    </IfModule>

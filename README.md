# everything-modsecurity
Some scripts and information when working with ModSecurity WAF (libmodsecurity).

## Some information
[ModSecurity WAF](https://github.com/owasp-modsecurity/ModSecurity) used to be a module for Apache HTTP Server (httpd), but now they have moved to support more web server engine like NGINX, IIS. Therefore, there are 2 projects running simutaneously:
- [ModSecurity for Apache](https://github.com/owasp-modsecurity/ModSecurity/tree/v2/master) - running version 2.x, support for version [3.x](https://github.com/owasp-modsecurity/ModSecurity-apache) is being developed - not for production.
- [libmodsecurity](https://github.com/owasp-modsecurity/ModSecurity) is the main project, from an Apache HTTPd module, now they become a standalone library, support more platform.

More information about this can be found [here](https://github.com/owasp-modsecurity/ModSecurity?tab=readme-ov-file#what-is-the-difference-between-this-project-and-the-old-modsecurity-v2xx).
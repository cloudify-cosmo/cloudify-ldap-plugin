# cloudify-ldap-plugin
The Cloudify LDAP security plugin provides the ability to authenticate users against any LDAP endpoint.

# Installation
The LDAP python dependency `python-ldap`, included in this project, requires system level dependencies e.g openldap-devel, python-devel, and gcc in order to install.
To avoid the need for the above compilation tools (python-devel, gcc), a [Wagon](https://github.com/cloudify-cosmo/wagon.git) package should be created and installed as a [rest plugin](http://docs.getcloudify.org/3.3.0/manager/security/#packaging-configuring-and-installing-custom-implementations).

# Bootstrapping using the LDAP authentication plugin
Since the `python-ldap` package requires system level dependencies even if a [Wagon](https://github.com/cloudify-cosmo/wagon.git) package is used, it is required to install these system level dependencies using a customized userdata script.
- No Wagon package: Userdata script should include `sudo yum install python-devel openldap-devel gcc -y`
- Using Wagon package: Userdata script should only include `sudo yum openldap-devel -y`

Root Login
-----------
This element assigns a password to the root account in the image.

This is useful when booting outside of a cloud environment (e.g. manually via
kvm) and for testing.

To login to VM, goto GUI console and enter the root credentials.
To enable or disable password based login over ssh set the parameter below
in ssh config file to yes or no respectively
    PasswordAuthentication no

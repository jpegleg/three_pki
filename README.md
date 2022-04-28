# three_pki
three_pki is a jwt auth rust program for executing shell openssl that signs csrs with single use CAs.

This program was created from https://github.com/jpegleg/fixadm as a starting point.

See prototype https://github.com/jpegleg/osprey_validator/tree/main/docker/osprey_3 usage demo.

The /opt/jwt/webtmp/CSR.csr file is written by the web (cgi) program as received by authenticated user.

There is a single file handle, so multiple simultaneous user action can have conflicts, although the action is 
fast enough and a retry works if such a collision occurs. Perhaps ideally there is not many users, each
application team would have their own instance of three_pki specific to them, segmenting application auth per service.

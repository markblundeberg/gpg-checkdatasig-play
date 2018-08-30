#!/bin/sh

#faketime -f "2020-01-01 00:00:00" gpg -b --default-key B787AA787A8A56445FF0BDCC2D91CAD9873ECC6A testmsg 
#faketime -f "2020-01-01 00:00:00" gpg -bt --default-key B787AA787A8A56445FF0BDCC2D91CAD9873ECC6A -o testmsg.sig.text testmsg

echo
gpg -vv --verify testmsg.sig testmsg
echo
gpg -vv --verify testmsg.sig.text testmsg
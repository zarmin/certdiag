# Trust stores are data you can list and diff. Offline.
Output ../docs/assets/demo-store.gif
Source header.tape
Set Height 720

Hide
Type `export PATH="$PWD/../certdiag_app/dist:$PATH" CERTDIAG_CONFIG=/tmp/certdiag-demo.yaml PS1="$ "` Enter
Type "cd /tmp/certdiag-demo && clear" Enter
Show
Sleep 1s
Type "certdiag store -f truststore.jks" Sleep 400ms Enter
Sleep 4s

Type "certdiag store diff truststore-old.jks truststore.jks" Sleep 400ms Enter
Sleep 5s

Type "echo $?" Sleep 300ms Enter
Sleep 3s

# What is in this directory, and how does it fit together. Offline.
Output ../docs/assets/demo-scan.gif
Source header.tape
Set Height 520

Hide
Type `export PATH="$PWD/../certdiag_app/dist:$PATH" CERTDIAG_CONFIG=/tmp/certdiag-demo.yaml PS1="$ "` Enter
Type "cd /tmp/certdiag-demo && clear" Enter
Show
Sleep 1s
Type "certdiag api.example.com.crt -D" Sleep 400ms Enter
Sleep 8s

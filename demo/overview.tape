# Hero: it finds the problem, explains it, and there is a UI. Offline.
Output ../docs/assets/demo-overview.gif
Source header.tape
Set Height 560

Hide
Type `export PATH="$PWD/../certdiag_app/dist:$PATH" CERTDIAG_CONFIG=/tmp/certdiag-demo.yaml PS1="$ "` Enter
Type "cd /tmp/certdiag-demo && clear" Enter
Show
Sleep 1s
Type "certdiag check ." Sleep 400ms Enter
Sleep 5s

Type "clear" Enter
Sleep 400ms
Type "certdiag verify --trust-file root-ca.crt fullchain.pem" Sleep 400ms Enter
Sleep 4s

Type "clear" Enter
Sleep 400ms
Type "certdiag tui ." Sleep 400ms Enter
Sleep 2500ms
Down Sleep 600ms
Down Sleep 3500ms

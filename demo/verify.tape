# The works-in-curl bug: a leaf without its intermediate. Offline.
Output ../docs/assets/demo-verify.gif
Source header.tape
Set Height 640

Hide
Type `export PATH="$PWD/../certdiag_app/dist:$PATH" CERTDIAG_CONFIG=/tmp/certdiag-demo.yaml PS1="$ "` Enter
Type "cd /tmp/certdiag-demo && clear" Enter
Show
Sleep 1s
Type "certdiag verify --trust-file root-ca.crt api.example.com.crt" Sleep 400ms Enter
Sleep 5s

Type "# the leaf alone does not chain up. send the intermediate too:" Sleep 300ms Enter
Sleep 800ms
Type "certdiag verify --trust-file root-ca.crt fullchain.pem" Sleep 400ms Enter
Sleep 5s

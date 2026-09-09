# What a client on this network sees. Needs network at render time.
Output ../docs/assets/demo-remote.gif
Source header.tape
Set Height 460

Hide
Type `export PATH="$PWD/../certdiag_app/dist:$PATH" CERTDIAG_CONFIG=/tmp/certdiag-demo.yaml PS1="$ "` Enter
Type "cd /tmp/certdiag-demo && clear" Enter
Show
Sleep 1s
Type "certdiag remote check expired.badssl.com" Sleep 400ms Enter
Sleep 6s

Type "clear" Enter
Sleep 400ms
Type "certdiag remote check www.example.com" Sleep 400ms Enter
Sleep 6s

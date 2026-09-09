# TLS 1.3 encrypts the Certificate message. Say so, then decrypt it. Offline.
Output ../docs/assets/demo-pcap.gif
Source header.tape
Set Height 380

Hide
Type `export PATH="$PWD/../certdiag_app/dist:$PATH" CERTDIAG_CONFIG=/tmp/certdiag-demo.yaml PS1="$ "` Enter
Type "cd /tmp/certdiag-demo && clear" Enter
Show
Sleep 1s
Type "certdiag pcap check capture.pcap" Sleep 400ms Enter
Sleep 4s

Type "certdiag pcap check capture.pcap --keylog capture.keylog" Sleep 400ms Enter
Sleep 5s

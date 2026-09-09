# TUI: the lister and its column editor. Offline.
Output ../docs/assets/demo-tui-lister.gif
Source header.tape
Set Height 720

Hide
Type `export PATH="$PWD/../certdiag_app/dist:$PATH" CERTDIAG_CONFIG=/tmp/certdiag-demo.yaml PS1="$ "` Enter
Type "cd /tmp/certdiag-demo && clear" Enter
Show
Sleep 1s
Type "certdiag tui ." Sleep 400ms Enter
Sleep 2500ms

# the column editor: drop ISSUER, add SANs and WARNINGS; the tree follows live
Type "C" Sleep 2s
Down Sleep 400ms
Space Sleep 1200ms
Down Sleep 250ms
Down Sleep 250ms
Down Sleep 250ms
Down Sleep 400ms
Space Sleep 1200ms
Down Sleep 250ms
Down Sleep 250ms
Down Sleep 400ms
Space Sleep 1500ms
Escape Sleep 3s

# fold the bundles
Type "z" Sleep 4s

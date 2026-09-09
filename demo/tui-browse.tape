# TUI: tree, detail, search, then renew the expired certificate. Offline.
Output ../docs/assets/demo-tui-browse.gif
Source header.tape
Set Height 620

Hide
Type `export PATH="$PWD/../certdiag_app/dist:$PATH" CERTDIAG_CONFIG=/tmp/certdiag-demo.yaml PS1="$ "` Enter
Type "cd /tmp/certdiag-demo && clear" Enter
Show
Sleep 1s
Type "certdiag tui ." Sleep 400ms Enter
Sleep 2500ms

# down to legacy.example.com.crt, the expired one
Down 11 Sleep 1500ms

# full detail
Enter Sleep 3s
Escape Sleep 800ms

# search narrows the tree to the expired certificate
Type "/" Sleep 400ms
Type "legacy" Sleep 1500ms
Enter Sleep 1500ms

# actions on a certificate: renew it with a fresh key, signed by the CA found next to it
Type "a" Sleep 2s
Type "r" Sleep 2s
Tab Sleep 300ms
Right Sleep 800ms
Tab Sleep 200ms
Tab Sleep 200ms
Tab Sleep 300ms
Right Sleep 300ms
Right Sleep 800ms
Tab Sleep 200ms
Tab Sleep 400ms
Enter Sleep 800ms
Tab Sleep 300ms
Type "legacy-renewed.crt" Sleep 500ms
Enter Sleep 600ms
Tab Sleep 400ms
Enter Sleep 800ms
Tab Sleep 300ms
Type "legacy-renewed.key" Sleep 500ms
Enter Sleep 1s
Alt+Enter Sleep 4s

Sleep 2s

# TUI: multi-select the leaf, its key and the intermediate, bundle them as PEM. Offline.
Output ../docs/assets/demo-tui-bundle.gif
Source header.tape
Set Height 620

Hide
Type `export PATH="$PWD/../certdiag_app/dist:$PATH" CERTDIAG_CONFIG=/tmp/certdiag-demo.yaml PS1="$ "` Enter
Type "cd /tmp/certdiag-demo && clear" Enter
Show
Sleep 1s
Type "certdiag tui ." Sleep 400ms Enter
Sleep 2500ms

# multi-select mode
Type "m" Sleep 1500ms
Space Sleep 700ms
Down Sleep 300ms
Space Sleep 700ms
Down 4 Sleep 500ms
Space Sleep 1500ms

# the bundle form: PEM, three items, output file
Enter Sleep 2500ms
Tab Sleep 400ms
Enter Sleep 800ms
Tab Sleep 300ms
Type "api-bundle.pem" Sleep 500ms
Enter Sleep 1200ms
Alt+Enter Sleep 4s

Sleep 2s

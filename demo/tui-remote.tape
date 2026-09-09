# TUI: the remote fetcher. Needs network at render time.
Output ../docs/assets/demo-tui-remote.gif
Source header.tape
Set Height 620

Hide
Type `export PATH="$PWD/../certdiag_app/dist:$PATH" CERTDIAG_CONFIG=/tmp/certdiag-demo.yaml PS1="$ "` Enter
Type "cd /tmp/certdiag-demo && clear" Enter
Show
Sleep 1s
Type "certdiag tui ." Sleep 400ms Enter
Sleep 2500ms

# Functions menu, Remote Fetch
Type "F" Sleep 2s
Type "2" Sleep 1500ms
Type "www.example.com" Sleep 1200ms
Alt+Enter Sleep 4s

# the served chain is a tree like any other
Down Sleep 1200ms
Enter Sleep 3s
Escape Sleep 1s

# and the check suite runs on it
Type "c" Sleep 3500ms
Escape Sleep 1500ms

Sleep 2s

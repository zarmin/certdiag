# Findings and exit codes, the CI story. Offline.
Output ../docs/assets/demo-check.gif
Source header.tape
Set Height 640

Hide
Type `export PATH="$PWD/../certdiag_app/dist:$PATH" CERTDIAG_CONFIG=/tmp/certdiag-demo.yaml PS1="$ "` Enter
Type "cd /tmp/certdiag-demo && clear" Enter
Show
Sleep 1s
Type "certdiag check ." Sleep 400ms Enter
Sleep 5s

Type "clear" Enter
Sleep 400ms
Type "certdiag check . --severity critical" Sleep 400ms Enter
Sleep 3s

Type "echo $?" Sleep 300ms Enter
Sleep 1500ms
Type "# exit 2: critical findings. 1: warnings only. 0: clean. Ready for CI." Sleep 300ms Enter
Sleep 4s

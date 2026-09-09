package filepicker

import "errors"

var ErrCancelled = errors.New("user cancelled")
var ErrNotRun = errors.New("Run() has not been called")

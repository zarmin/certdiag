package cmdutil

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/PaesslerAG/jsonpath"
)

// OutputJSONPathPrefix marks a --output value that carries a JSONPath
// expression, e.g. --output jsonpath=$.files[0].filename
const OutputJSONPathPrefix = "jsonpath="

// EvalJSONPath evaluates a JSONPath expression against JSON data and returns the
// matched value(s) as text. Scalars print bare, a matched array prints one entry
// per line, and objects or nested values print as compact JSON. A leading "."
// is accepted as kubectl-style shorthand for "$.", and surrounding {} braces are
// stripped.
func EvalJSONPath(jsonData []byte, expr string) (string, error) {
	expr = normalizeJSONPath(expr)
	if expr == "" {
		return "", fmt.Errorf("empty jsonpath expression")
	}

	var doc any
	if err := json.Unmarshal(jsonData, &doc); err != nil {
		return "", fmt.Errorf("parsing json for jsonpath: %w", err)
	}

	result, err := jsonpath.Get(expr, doc)
	if err != nil {
		return "", fmt.Errorf("jsonpath %q: %w", expr, err)
	}

	return formatJSONPathResult(result), nil
}

func normalizeJSONPath(expr string) string {
	expr = strings.TrimSpace(expr)
	expr = strings.TrimPrefix(expr, "{")
	expr = strings.TrimSuffix(expr, "}")
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, ".") {
		expr = "$" + expr
	}
	return expr
}

func formatJSONPathResult(v any) string {
	if arr, ok := v.([]any); ok {
		lines := make([]string, len(arr))
		for i, e := range arr {
			lines[i] = formatJSONPathValue(e)
		}
		return strings.Join(lines, "\n")
	}
	return formatJSONPathValue(v)
}

func formatJSONPathValue(v any) string {
	switch val := v.(type) {
	case nil:
		return ""
	case string:
		return val
	case bool:
		return strconv.FormatBool(val)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

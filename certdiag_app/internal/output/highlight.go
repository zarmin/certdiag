package output

import (
	"regexp"
	"strings"
	"unicode"
)

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func HighlightMatches(text, query string) string {
	if query == "" || !ColorsEnabled {
		return text
	}

	lowerQuery := strings.ToLower(query)
	result := strings.Builder{}
	result.Grow(len(text) * 2)

	segments := splitByANSI(text)

	for _, seg := range segments {
		if seg.isANSI {
			result.WriteString(seg.text)
		} else {
			result.WriteString(highlightSegment(seg.text, lowerQuery))
		}
	}

	return result.String()
}

type textSegment struct {
	text   string
	isANSI bool
}

func splitByANSI(text string) []textSegment {
	var segments []textSegment
	lastEnd := 0

	matches := ansiEscapePattern.FindAllStringIndex(text, -1)

	for _, match := range matches {
		if match[0] > lastEnd {
			segments = append(segments, textSegment{
				text:   text[lastEnd:match[0]],
				isANSI: false,
			})
		}
		segments = append(segments, textSegment{
			text:   text[match[0]:match[1]],
			isANSI: true,
		})
		lastEnd = match[1]
	}

	if lastEnd < len(text) {
		segments = append(segments, textSegment{
			text:   text[lastEnd:],
			isANSI: false,
		})
	}

	return segments
}

func highlightSegment(text, lowerQuery string) string {
	if text == "" {
		return text
	}

	lowerBuilder := strings.Builder{}
	lowerBuilder.Grow(len(text))
	origOffsets := make([]int, 0, len(text)+1)
	for i, r := range text {
		start := lowerBuilder.Len()
		lowerBuilder.WriteRune(unicode.ToLower(r))
		for j := start; j < lowerBuilder.Len(); j++ {
			origOffsets = append(origOffsets, i)
		}
	}
	origOffsets = append(origOffsets, len(text))
	lowerText := lowerBuilder.String()

	result := strings.Builder{}
	result.Grow(len(text) * 2)

	lastEnd := 0
	for {
		idx := strings.Index(lowerText[lastEnd:], lowerQuery)
		if idx == -1 {
			result.WriteString(text[origOffsets[lastEnd]:])
			break
		}

		matchStart := lastEnd + idx
		matchEnd := matchStart + len(lowerQuery)

		result.WriteString(text[origOffsets[lastEnd]:origOffsets[matchStart]])
		result.WriteString(HighlightColor.Sprint(text[origOffsets[matchStart]:origOffsets[matchEnd]]))

		lastEnd = matchEnd
	}

	return result.String()
}

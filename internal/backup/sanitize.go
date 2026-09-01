package backup

import "strings"

// sanitizeText scrubs control characters out of text that came from an
// artifact written on another machine. The kit rule is that every parser
// treats its input as hostile; an artifact moves between hosts, so a part's
// bytes are exactly that. Printable characters, plus the newline and tab that
// structure a config, are kept; every other control character (including a
// carriage return, a NUL, or an escape that could drive a terminal) is dropped.
//
// It is used on the way in — when a part is read out of the tar — so nothing
// downstream, a preview or a diff, ever renders an unsanitized byte.
func sanitizeText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r == '\r':
			// Fold a CRLF or a bare CR into a newline, so a config written on
			// one platform reads the same on another without smuggling a CR.
			b.WriteRune('\n')
		case r < 0x20 || r == 0x7f:
			// Other C0 controls and DEL are dropped: they carry no config
			// meaning and can drive a terminal that later prints the preview.
		case r >= 0x80 && r <= 0x9f:
			// C1 controls, the ones an escape sequence can smuggle in, dropped.
		case r == 0xfffd:
			// The replacement rune marks bytes that were not valid UTF-8;
			// dropping it keeps the sanitized text well-formed.
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitizeName scrubs a part's base filename to a safe token before it is used
// to build a Sources key. A name is a single path segment: no separator, no
// parent reference, no control character. A name that does not survive this is
// rejected by the caller, never guessed at.
func sanitizeName(name string) string {
	if name == "" {
		return ""
	}
	// A traversal attempt or an absolute path is not a base name.
	if strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return ""
	}
	cleaned := sanitizeText(name)
	// A name may not carry a newline or tab either: those survive sanitizeText
	// as structure, but a filename has none.
	if strings.ContainsAny(cleaned, "\n\t") || cleaned != name {
		return ""
	}
	return cleaned
}

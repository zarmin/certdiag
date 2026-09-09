package config

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

func RewriteEncryptedPasswords(rawYAML []byte, replacements map[string]string) ([]byte, error) {
	var rootNode yaml.Node
	if err := yaml.Unmarshal(rawYAML, &rootNode); err != nil {
		return nil, err
	}

	replaceInNode(&rootNode, replacements)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&rootNode); err != nil {
		return nil, err
	}
	enc.Close()

	return buf.Bytes(), nil
}

func replaceInNode(node *yaml.Node, replacements map[string]string) {
	if node.Kind == yaml.ScalarNode {
		if newVal, ok := replacements[node.Value]; ok {
			node.Value = newVal
		}
		return
	}
	for _, child := range node.Content {
		replaceInNode(child, replacements)
	}
}

// RewriteTUIColumns rewrites the defaults.tui.columns list in the given YAML bytes,
// preserving all existing comments and structure. Creates nodes as needed.
// RewriteTrustStoreOptions persists the trust store view's columns and
// grouping mode without disturbing the Cert Lister's own column set.
func RewriteTrustStoreOptions(rawYAML []byte, columns []string, grouping string) ([]byte, error) {
	var rootNode yaml.Node
	if err := yaml.Unmarshal(rawYAML, &rootNode); err != nil {
		return nil, err
	}

	if rootNode.Kind != yaml.DocumentNode || len(rootNode.Content) == 0 {
		return nil, fmt.Errorf("unexpected yaml structure: not a document")
	}
	root := rootNode.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("unexpected yaml structure: root is not a mapping")
	}

	defaults := getOrCreateMappingChild(root, "defaults")
	tui := getOrCreateMappingChild(defaults, "tui")

	seqNode := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, col := range columns {
		seqNode.Content = append(seqNode.Content, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Value: col,
			Tag:   "!!str",
		})
	}

	replaced := false
	for i := 0; i+1 < len(tui.Content); i += 2 {
		if tui.Content[i].Value == "trust_store_columns" {
			tui.Content[i+1] = seqNode
			replaced = true
			break
		}
	}
	if !replaced {
		tui.Content = append(tui.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "trust_store_columns", Tag: "!!str"},
			seqNode,
		)
	}

	if grouping != "" {
		setScalarInMapping(tui, "trust_store_grouping", grouping, "!!str")
	}

	return encodeNode(&rootNode)
}

func RewriteTUIColumns(rawYAML []byte, columns []string) ([]byte, error) {
	var rootNode yaml.Node
	if err := yaml.Unmarshal(rawYAML, &rootNode); err != nil {
		return nil, err
	}

	if rootNode.Kind != yaml.DocumentNode || len(rootNode.Content) == 0 {
		return nil, fmt.Errorf("unexpected yaml structure: not a document")
	}
	root := rootNode.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("unexpected yaml structure: root is not a mapping")
	}

	defaults := getOrCreateMappingChild(root, "defaults")
	tui := getOrCreateMappingChild(defaults, "tui")

	// Build new sequence node
	seqNode := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, col := range columns {
		seqNode.Content = append(seqNode.Content, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Value: col,
			Tag:   "!!str",
		})
	}

	// Replace existing columns value or append new key-value pair
	for i := 0; i+1 < len(tui.Content); i += 2 {
		if tui.Content[i].Value == "columns" {
			tui.Content[i+1] = seqNode
			return encodeNode(&rootNode)
		}
	}
	tui.Content = append(tui.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: "columns", Tag: "!!str"},
		seqNode,
	)
	return encodeNode(&rootNode)
}

type TUIOptionsForSave struct {
	Recursive         bool
	MaxDepth          int
	FileSignatureScan bool
	AutoDiscover      bool
	PathDisplay       string
}

func RewriteTUIOptions(rawYAML []byte, opts TUIOptionsForSave) ([]byte, error) {
	var rootNode yaml.Node
	if err := yaml.Unmarshal(rawYAML, &rootNode); err != nil {
		return nil, err
	}

	if rootNode.Kind != yaml.DocumentNode || len(rootNode.Content) == 0 {
		return nil, fmt.Errorf("unexpected yaml structure: not a document")
	}
	root := rootNode.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("unexpected yaml structure: root is not a mapping")
	}

	defaults := getOrCreateMappingChild(root, "defaults")
	tui := getOrCreateMappingChild(defaults, "tui")

	setScalarInMapping(tui, "recursive", fmt.Sprintf("%t", opts.Recursive), "!!bool")
	setScalarInMapping(tui, "max_depth", fmt.Sprintf("%d", opts.MaxDepth), "!!int")
	setScalarInMapping(tui, "file_signature_scan", fmt.Sprintf("%t", opts.FileSignatureScan), "!!bool")
	setScalarInMapping(tui, "auto_discover", fmt.Sprintf("%t", opts.AutoDiscover), "!!bool")
	setScalarInMapping(tui, "path_display", opts.PathDisplay, "!!str")

	return encodeNode(&rootNode)
}

func setScalarInMapping(mapping *yaml.Node, key, value, tag string) {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			mapping.Content[i+1].Value = value
			mapping.Content[i+1].Tag = tag
			mapping.Content[i+1].Kind = yaml.ScalarNode
			return
		}
	}
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: key, Tag: "!!str"},
		&yaml.Node{Kind: yaml.ScalarNode, Value: value, Tag: tag},
	)
}

// getOrCreateMappingChild finds or creates a mapping-valued child key inside a parent mapping.
func getOrCreateMappingChild(parent *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			child := parent.Content[i+1]
			// Coerce null/scalar to mapping (e.g. "defaults:" with no value)
			if child.Kind != yaml.MappingNode {
				child.Kind = yaml.MappingNode
				child.Tag = "!!map"
				child.Value = ""
				child.Content = nil
			}
			return child
		}
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key, Tag: "!!str"}
	valNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	parent.Content = append(parent.Content, keyNode, valNode)
	return valNode
}

func encodeNode(node *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(node); err != nil {
		return nil, err
	}
	enc.Close()
	return buf.Bytes(), nil
}

// RewriteOutputFingerprintFormat persists the fingerprint display format under
// defaults.output. It lives there rather than under defaults.tui because the
// setting also governs CLI output (`list -d`, `diff -d`, `remote -d`).
func RewriteOutputFingerprintFormat(rawYAML []byte, format string) ([]byte, error) {
	var rootNode yaml.Node
	if err := yaml.Unmarshal(rawYAML, &rootNode); err != nil {
		return nil, err
	}

	if rootNode.Kind != yaml.DocumentNode || len(rootNode.Content) == 0 {
		return nil, fmt.Errorf("unexpected yaml structure: not a document")
	}
	root := rootNode.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("unexpected yaml structure: root is not a mapping")
	}

	defaults := getOrCreateMappingChild(root, "defaults")
	out := getOrCreateMappingChild(defaults, "output")
	setScalarInMapping(out, "fingerprint_format", format, "!!str")

	return encodeNode(&rootNode)
}

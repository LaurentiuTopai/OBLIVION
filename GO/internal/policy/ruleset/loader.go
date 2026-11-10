package ruleset

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
	"oblivion/internal/policy"
)

type disabledConfig struct {
	DisabledCategories []string `yaml:"disabled_categories"`
}

func LoadRules(rulesDir string) ([]policy.DeclarativeRule, error) {
	disabled, err := loadDisabled(filepath.Join(rulesDir, "disabled.yaml"))
	if err != nil {
		return nil, fmt.Errorf("disabled.yaml: %w", err)
	}

	disabledSet := make(map[string]bool, len(disabled))
	for _, cat := range disabled {
		disabledSet[cat] = true
	}

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("readdir %s: %w", rulesDir, err)
	}

	var all []policy.DeclarativeRule
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if disabledSet[entry.Name()] {
			continue
		}
		rulesFile := filepath.Join(rulesDir, entry.Name(), "rules.yaml")
		rules, err := loadFile(rulesFile)
		if err != nil {
			return nil, fmt.Errorf("category %s: %w", entry.Name(), err)
		}
		all = append(all, rules...)
	}
	return all, nil
}

func loadFile(path string) ([]policy.DeclarativeRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var rules []policy.DeclarativeRule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return rules, nil
}

func loadDisabled(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg disabledConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return cfg.DisabledCategories, nil
}

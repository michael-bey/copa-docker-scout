package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestParseDockerScoutReport(t *testing.T) {
	type args struct {
		file string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "valid nginx report",
			args:    args{file: "testdata/nginx-epss.json"},
			wantErr: false,
		},
		{
			name:    "invalid file path",
			args:    args{file: "testdata/nonexistent.json"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.args.file)
			if err != nil && !tt.wantErr {
				t.Errorf("Failed to read test file: %v", err)
				return
			}
			got, err := parse(data)
			if (err != nil) != tt.wantErr {
				t.Errorf("parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Verify the output is valid JSON and has the expected structure
				var manifest UpdateManifest
				if err := json.Unmarshal([]byte(got), &manifest); err != nil {
					t.Errorf("parse() output is not valid JSON: %v", err)
					return
				}
				// Verify required fields
				if manifest.APIVersion != "v1alpha1" {
					t.Errorf("parse() output has wrong API version: got %s, want v1alpha1", manifest.APIVersion)
				}
				if manifest.Metadata.OS.Type == "" {
					t.Error("parse() output missing OS type")
				}
				if manifest.Metadata.OS.Version == "" {
					t.Error("parse() output missing OS version")
				}
				if manifest.Metadata.Config.Arch == "" {
					t.Error("parse() output missing architecture")
				}
				if len(manifest.Updates) == 0 {
					t.Error("parse() output has no updates")
				}
				// Verify update structure
				for i, update := range manifest.Updates {
					if update.Name == "" {
						t.Errorf("Update %d missing name", i)
					}
					if update.InstalledVersion == "" {
						t.Errorf("Update %d missing installed version", i)
					}
					if update.VulnerabilityID == "" {
						t.Errorf("Update %d missing vulnerability ID", i)
					}
				}
			}
		})
	}
}

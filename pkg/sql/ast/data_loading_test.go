package ast

import "testing"

// Test StageParamsObject String()
func TestStageParamsObject(t *testing.T) {
	url := "s3://bucket/path"
	endpoint := "https://s3.amazonaws.com"
	integration := "my_integration"

	tests := []struct {
		name       string
		params     *StageParamsObject
		wantString string
	}{
		{
			name: "with URL only",
			params: &StageParamsObject{
				URL: &url,
			},
			wantString: "URL='s3://bucket/path'",
		},
		{
			name: "with URL and storage integration",
			params: &StageParamsObject{
				URL:                &url,
				StorageIntegration: &integration,
			},
			wantString: "URL='s3://bucket/path' STORAGE_INTEGRATION=my_integration",
		},
		{
			name: "with URL, integration, and endpoint",
			params: &StageParamsObject{
				URL:                &url,
				StorageIntegration: &integration,
				Endpoint:           &endpoint,
			},
			wantString: "URL='s3://bucket/path' STORAGE_INTEGRATION=my_integration ENDPOINT='https://s3.amazonaws.com'",
		},
		{
			name: "with credentials",
			params: &StageParamsObject{
				URL: &url,
				Credentials: DataLoadingOptions{
					Options: []DataLoadingOption{
						NewStringOption("AWS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
						NewStringOption("AWS_SECRET_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
					},
				},
			},
			wantString: "URL='s3://bucket/path' CREDENTIALS=(AWS_KEY_ID='AKIAIOSFODNN7EXAMPLE' AWS_SECRET_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')",
		},
		{
			name: "with encryption",
			params: &StageParamsObject{
				URL: &url,
				Encryption: DataLoadingOptions{
					Options: []DataLoadingOption{
						NewEnumOption("TYPE", "AWS_SSE_KMS"),
						NewStringOption("KMS_KEY_ID", "1234abcd-12ab-34cd-56ef-1234567890ab"),
					},
				},
			},
			wantString: "URL='s3://bucket/path' ENCRYPTION=(TYPE=AWS_SSE_KMS KMS_KEY_ID='1234abcd-12ab-34cd-56ef-1234567890ab')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.params.String(); got != tt.wantString {
				t.Errorf("StageParamsObject.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test DataLoadingOptions String()
func TestDataLoadingOptions(t *testing.T) {
	tests := []struct {
		name       string
		opts       *DataLoadingOptions
		wantString string
	}{
		{
			name: "empty options",
			opts: &DataLoadingOptions{
				Options: []DataLoadingOption{},
			},
			wantString: "",
		},
		{
			name: "single option",
			opts: &DataLoadingOptions{
				Options: []DataLoadingOption{
					NewStringOption("FORMAT_NAME", "CSV"),
				},
			},
			wantString: "FORMAT_NAME='CSV'",
		},
		{
			name: "multiple options",
			opts: &DataLoadingOptions{
				Options: []DataLoadingOption{
					NewStringOption("FORMAT_NAME", "CSV"),
					NewBooleanOption("SKIP_HEADER", true),
					NewEnumOption("COMPRESSION", "GZIP"),
				},
			},
			wantString: "FORMAT_NAME='CSV' SKIP_HEADER=true COMPRESSION=GZIP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.opts.String(); got != tt.wantString {
				t.Errorf("DataLoadingOptions.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test DataLoadingOption String()
func TestDataLoadingOption(t *testing.T) {
	tests := []struct {
		name       string
		opt        DataLoadingOption
		wantString string
	}{
		{
			name:       "string option",
			opt:        NewStringOption("FILE_FORMAT", "CSV"),
			wantString: "FILE_FORMAT='CSV'",
		},
		{
			name:       "boolean option true",
			opt:        NewBooleanOption("SKIP_HEADER", true),
			wantString: "SKIP_HEADER=true",
		},
		{
			name:       "boolean option false",
			opt:        NewBooleanOption("SKIP_BLANK_LINES", false),
			wantString: "SKIP_BLANK_LINES=false",
		},
		{
			name:       "enum option",
			opt:        NewEnumOption("COMPRESSION", "GZIP"),
			wantString: "COMPRESSION=GZIP",
		},
		{
			name:       "number option int",
			opt:        NewNumberOption("SKIP_LINES", 10),
			wantString: "SKIP_LINES=10",
		},
		{
			name:       "number option float",
			opt:        NewNumberOption("SIZE_LIMIT", 1024.5),
			wantString: "SIZE_LIMIT=1024.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.opt.String(); got != tt.wantString {
				t.Errorf("DataLoadingOption.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test StageLoadSelectItem String()
func TestStageLoadSelectItem(t *testing.T) {
	tests := []struct {
		name       string
		item       *StageLoadSelectItem
		wantString string
	}{
		{
			name: "simple file column",
			item: &StageLoadSelectItem{
				FileColNum: 1,
			},
			wantString: "$1",
		},
		{
			name: "with alias",
			item: &StageLoadSelectItem{
				Alias:      &Ident{Name: "t"},
				FileColNum: 2,
			},
			wantString: "t.$2",
		},
		{
			name: "with element",
			item: &StageLoadSelectItem{
				FileColNum: 1,
				Element:    &Ident{Name: "name"},
			},
			wantString: "$1:name",
		},
		{
			name: "with AS alias",
			item: &StageLoadSelectItem{
				FileColNum: 3,
				ItemAs:     &Ident{Name: "user_id"},
			},
			wantString: "$3 AS user_id",
		},
		{
			name: "complete with all parts",
			item: &StageLoadSelectItem{
				Alias:      &Ident{Name: "stage"},
				FileColNum: 5,
				Element:    &Ident{Name: "email"},
				ItemAs:     &Ident{Name: "user_email"},
			},
			wantString: "stage.$5:email AS user_email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.item.String(); got != tt.wantString {
				t.Errorf("StageLoadSelectItem.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test FileStagingCommand String()
func TestFileStagingCommand(t *testing.T) {
	pattern := ".*\\.csv"

	tests := []struct {
		name       string
		cmd        *FileStagingCommand
		wantString string
	}{
		{
			name: "without pattern",
			cmd: &FileStagingCommand{
				Stage: ObjectName{Name: "@my_stage"},
			},
			wantString: "@my_stage",
		},
		{
			name: "with pattern",
			cmd: &FileStagingCommand{
				Stage:   ObjectName{Name: "@my_stage/path"},
				Pattern: &pattern,
			},
			wantString: "@my_stage/path PATTERN='.*\\.csv'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cmd.String(); got != tt.wantString {
				t.Errorf("FileStagingCommand.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test helper functions
func TestDataLoadingOptionHelpers(t *testing.T) {
	t.Run("NewStringOption", func(t *testing.T) {
		opt := NewStringOption("KEY", "value")
		if opt.OptionName != "KEY" {
			t.Errorf("OptionName = %v, want KEY", opt.OptionName)
		}
		if opt.OptionType != DataLoadingOptionTypeString {
			t.Errorf("OptionType = %v, want DataLoadingOptionTypeString", opt.OptionType)
		}
		if opt.Value != "value" {
			t.Errorf("Value = %v, want value", opt.Value)
		}
	})

	t.Run("NewBooleanOption", func(t *testing.T) {
		opt := NewBooleanOption("ENABLED", true)
		if opt.OptionName != "ENABLED" {
			t.Errorf("OptionName = %v, want ENABLED", opt.OptionName)
		}
		if opt.OptionType != DataLoadingOptionTypeBoolean {
			t.Errorf("OptionType = %v, want DataLoadingOptionTypeBoolean", opt.OptionType)
		}
		if opt.Value != "true" {
			t.Errorf("Value = %v, want true", opt.Value)
		}
	})

	t.Run("NewEnumOption", func(t *testing.T) {
		opt := NewEnumOption("TYPE", "CSV")
		if opt.OptionName != "TYPE" {
			t.Errorf("OptionName = %v, want TYPE", opt.OptionName)
		}
		if opt.OptionType != DataLoadingOptionTypeEnum {
			t.Errorf("OptionType = %v, want DataLoadingOptionTypeEnum", opt.OptionType)
		}
		if opt.Value != "CSV" {
			t.Errorf("Value = %v, want CSV", opt.Value)
		}
	})

	t.Run("NewNumberOption", func(t *testing.T) {
		opt := NewNumberOption("COUNT", 42)
		if opt.OptionName != "COUNT" {
			t.Errorf("OptionName = %v, want COUNT", opt.OptionName)
		}
		if opt.OptionType != DataLoadingOptionTypeNumber {
			t.Errorf("OptionType = %v, want DataLoadingOptionTypeNumber", opt.OptionType)
		}
		if opt.Value != "42" {
			t.Errorf("Value = %v, want 42", opt.Value)
		}
	})
}

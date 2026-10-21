// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import "testing"

// TestRootCmdVersionUsesVersionVar guards the release ldflags contract:
// --version must print the Version variable, which release builds override
// with -X github.com/ajitpratap0/GoSQLX/cmd/gosqlx/cmd.Version=<tag>.
func TestRootCmdVersionUsesVersionVar(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must have a non-empty default for dev builds")
	}
	if rootCmd.Version != Version {
		t.Errorf("rootCmd.Version = %q, want Version %q", rootCmd.Version, Version)
	}
}

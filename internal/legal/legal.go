// Package legal carries the license texts of the open-source components that
// are built into VPNer, so that they travel with every copy of the program
// (vpner.exe is also published on its own). See LEGAL.md in the repository.
package legal

import _ "embed"

//go:generate go run ./gen

// FileName is the name the notices get next to an installed or portable
// vpner.exe.
const FileName = "THIRD_PARTY_NOTICES.txt"

//go:embed THIRD_PARTY_NOTICES.txt
var Notices string

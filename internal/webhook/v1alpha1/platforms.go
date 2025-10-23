package v1alpha1

import specs "github.com/opencontainers/image-spec/specs-go/v1"

var allowedPlatforms = []specs.Platform{
	// Linux platforms
	{OS: "linux", Architecture: "386"},
	{OS: "linux", Architecture: "amd64"},
	{OS: "linux", Architecture: "amd64", Variant: "v2"},
	{OS: "linux", Architecture: "amd64", Variant: "v3"},
	{OS: "linux", Architecture: "amd64", Variant: "v4"},
	{OS: "linux", Architecture: "arm", Variant: "v5"},
	{OS: "linux", Architecture: "arm", Variant: "v6"},
	{OS: "linux", Architecture: "arm", Variant: "v7"},
	{OS: "linux", Architecture: "arm64"},
	{OS: "linux", Architecture: "arm64", Variant: "v8"},
	{OS: "linux", Architecture: "ppc64"},
	{OS: "linux", Architecture: "ppc64le"},
	{OS: "linux", Architecture: "mips"},
	{OS: "linux", Architecture: "mipsle"},
	{OS: "linux", Architecture: "mips64"},
	{OS: "linux", Architecture: "mips64le"},
	{OS: "linux", Architecture: "s390x"},
	{OS: "linux", Architecture: "riscv64"},
	{OS: "linux", Architecture: "loong64"},

	// Darwin (macOS) platforms
	{OS: "darwin", Architecture: "amd64"},
	{OS: "darwin", Architecture: "amd64", Variant: "v2"},
	{OS: "darwin", Architecture: "amd64", Variant: "v3"},
	{OS: "darwin", Architecture: "arm64"},
	{OS: "darwin", Architecture: "arm64", Variant: "v8"},

	// Windows platforms
	{OS: "windows", Architecture: "386"},
	{OS: "windows", Architecture: "amd64"},
	{OS: "windows", Architecture: "amd64", Variant: "v2"},
	{OS: "windows", Architecture: "amd64", Variant: "v3"},
	{OS: "windows", Architecture: "arm"},
	{OS: "windows", Architecture: "arm", Variant: "v7"},
	{OS: "windows", Architecture: "arm64"},
}

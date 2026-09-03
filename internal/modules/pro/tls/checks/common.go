package checks

const moduleName = "tls"

var internalSANPatterns = []string{
	".internal", ".local", ".corp", ".lan", ".svc.cluster", "localhost",
}

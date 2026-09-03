package checks

const moduleName = "redirects"

// RedirectParams are query parameter names commonly used for redirect destinations.
var RedirectParams = []string{
	"redirect", "redirect_uri", "redirect_url", "returnUrl", "return_url",
	"return", "next", "continue", "url", "goto", "target", "dest",
	"destination", "RelayState", "post_logout_redirect_uri", "back",
	"callback", "redir", "ref", "referer",
}

var debugIndicators = []string{
	"stack trace", "traceback", "exception", "at sun.reflect",
	"at java.", "goroutine ", "panic:", "NullPointerException",
	"Internal Server Error", "django.core", "rails", "Caused by:",
}

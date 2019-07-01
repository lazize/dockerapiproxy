package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"gopkg.in/ldap.v2"
)

var (
	conf  config
	proxy *httputil.ReverseProxy

	tlsConfig = &tls.Config{
		// Avoids most of the memorably-named TLS attacks
		MinVersion: tls.VersionTLS12,
		// Causes servers to use Go's default ciphersuite preferences,
		// which are tuned to avoid attacks. Does nothing on clients.
		PreferServerCipherSuites: true,
		// Only use curves which have constant-time implementations
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
		},
	}
)

func main() {
	log.SetOutput(os.Stdout)

	// Config
	configPtr := flag.String("config", "", "Config file to be used. Must be JSON format!")
	flag.Parse()

	if *configPtr == "" {
		err := parseConfig(&conf)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		err := parseConfigFile(&conf, *configPtr)
		if err != nil {
			log.Fatal(err)
		}
	}
	conf.notAllowedRegexp = makeRegexpSlice(conf.NotAllowed)
	conf.AllowedOnAllVerbs.allowedRegexp = makeRegexpSlice(conf.AllowedOnAllVerbs.Allowed)
	conf.AllowedOnAllVerbs.exceptionRegexp = makeRegexpSlice(conf.AllowedOnAllVerbs.Exception)

	// Reverse Proxy
	registryURL, err := url.Parse("http://localhost")
	if err != nil {
		log.Fatal(err)
	}

	dockerSocketAddr := &net.UnixAddr{Name: conf.DockerSocket, Net: "unix"}

	proxy = httputil.NewSingleHostReverseProxy(registryURL)
	proxy.Transport = &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.DialUnix("unix", nil, dockerSocketAddr)
		},
	}

	// Interrupt
	signalChan := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		// Wait for interruption signal, can be CTRL-C
		// or error from one of goroutine's below
		<-signalChan
		signal.Stop(signalChan)
		close(signalChan)

		log.Println("Interrupt")
		close(done)
	}()

	// Listen on HTTPS
	go listenAndServeHTTPS(signalChan)

	// Wait for cleanup be done
	<-done
}

func makeRegexpSlice(expressions []string) []*regexp.Regexp {
	returnSlice := make([]*regexp.Regexp, len(conf.NotAllowed))
	for i, item := range expressions {
		returnSlice[i] = regexp.MustCompile(item)
	}
	return returnSlice
}

func listenAndServeHTTPS(ch chan<- os.Signal) {
	httpsMux := http.NewServeMux()
	httpsMux.HandleFunc("/", wrapHandlerWithLogging(handleCoordinator))

	addr := fmt.Sprintf("%v:%v", conf.Address, conf.SecurePort)
	log.Println("HTTPS", addr)
	server := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler:   httpsMux,
	}

	err := server.ListenAndServeTLS(conf.Certificate, conf.CertificateKey)
	if err != nil {
		log.Println("HTTPS", err)
	}
	ch <- os.Interrupt
}

func wrapHandlerWithLogging(wrappedHandler http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		method := r.Method
		path := r.URL.Path
		query := r.URL.RawQuery
		r.URL.Query().Encode()
		if query == "" {
			query = "-"
		}
		remoteAddr := r.RemoteAddr

		lrw := newLoggingResponseWriter(w)
		wrappedHandler(lrw, r)

		elapsed := time.Since(start)
		log.Println(start.Format(time.RFC3339), remoteAddr, lrw.username, method, path, query, lrw.statusCode, elapsed)
	})
}

func handleCoordinator(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"GLOBAL AD Account\"")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	w.(*loggingResponseWriter).username = username

	// Authentication using LDAP
	authorized, err := authorizeUser(username, password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !authorized {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	stop := restrictedResource(w, r)
	if stop {
		return
	}

	// If user is authenticated and the resource is not restricted,
	// redirect the request to docker socket
	proxy.ServeHTTP(w, r)
}

func restrictedResource(w http.ResponseWriter, r *http.Request) (stop bool) {
	// log.Println(r.URL)
	// log.Println(r.URL.EscapedPath())
	// log.Println(r.URL.RequestURI())

	for _, expr := range conf.notAllowedRegexp {
		match := expr.MatchString(r.URL.EscapedPath())
		if match {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return true
		}
	}

	if r.Method != "GET" {
		// Check if the VERB is allowed in this URL
		mustStop := true
		for _, expr := range conf.AllowedOnAllVerbs.allowedRegexp {
			match := expr.MatchString(r.URL.EscapedPath())
			if match {
				mustStop = false
				break
			}
		}

		// Check not allowed exception
		if !mustStop {
			for _, expr := range conf.AllowedOnAllVerbs.exceptionRegexp {
				match := expr.MatchString(r.URL.EscapedPath())
				if match {
					mustStop = true
					break
				}
			}
		}

		if mustStop {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return true
		}
	}

	return false
}

func authorizeUser(username string, password string) (bool, error) {
	bindusername := conf.LDAPBindUser
	bindpassword := conf.LDAPBindPass

	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", conf.LDAPServer, conf.LDAPPort))
	if err != nil {
		return false, err
	}
	defer l.Close()

	// Reconnect with TLS
	err = l.StartTLS(&tls.Config{ServerName: conf.LDAPTLSServerName})
	if err != nil {
		return false, err
	}

	// First bind with a read only user
	err = l.Bind(bindusername, bindpassword)
	if err != nil {
		return false, err
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		conf.LDAPBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", username),
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return false, err
	}

	if len(sr.Entries) != 1 {
		//return false, errors.New("User does not exist or too many entries returned")
		return false, nil
	}

	userdn := sr.Entries[0].DN

	// Bind as the user to verify their password
	err = l.Bind(userdn, password)
	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials):
		return false, nil
	case err != nil:
		return false, err
	}

	return true, nil
}

// Config : Struct to match JSON config file
type config struct {
	Address           string
	SecurePort        int
	Certificate       string
	CertificateKey    string
	LDAPServer        string
	LDAPPort          int
	LDAPTLSServerName string
	LDAPBindUser      string
	LDAPBindPass      string
	LDAPBaseDN        string
	DockerSocket      string
	NotAllowed        []string
	notAllowedRegexp  []*regexp.Regexp
	AllowedOnAllVerbs struct {
		Allowed         []string
		allowedRegexp   []*regexp.Regexp
		Exception       []string
		exceptionRegexp []*regexp.Regexp
	}
}

// ParseConfig : Load default config file, in JSON format
func parseConfig(v interface{}) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	config := exe + ".conf"

	return parseConfigFile(v, config)
}

// ParseConfigFile : Parse config file to some struct.
// Config file must be in JSON format.
func parseConfigFile(v interface{}, fileName string) error {
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer f.Close()

	err = json.NewDecoder(f).Decode(v)
	if err != nil {
		return err
	}
	return nil
}

func newLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{w, http.StatusOK, "-"}
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	username   string
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

/*
 * Copyright (C) 2020 github.com/t1ra
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a
 * copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package main

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/semaphore"

	"github.com/gorilla/handlers"
)

// Response is returned to the frontend after working with whatever data is provided.
type Response struct {
	Error  string `json:"error"`
	Result string `json:"result"`
}

var (
	port    = flag.String("port", "1312", "Port to host æblør on. Default: 1312")
	verbose = flag.Bool("verbose", false, "Print usage and other useful information")
)

func main() {
	fileServer := http.FileServer(http.Dir("static/"))
	/* / endpoint */
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fileServer.ServeHTTP(w, r)
	})
	/* /hash endpoint */
	http.HandleFunc("/hash", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		toHash := r.PostFormValue("string")
		algorithm := r.PostFormValue("hash")
		result, err := Hash(toHash, algorithm)
		if err != nil {
			JSONResponse(w, Response{Error: err.Error()})
			return
		}
		JSONResponse(w, Response{Result: result})
	})
	/* /generate endpoint */
	http.HandleFunc("/generate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		length, err := strconv.Atoi(r.PostFormValue("length"))
		if err != nil {
			JSONResponse(w, Response{Error: err.Error()})
			return
		}
		charset := r.PostFormValue("charset")
		result := Generate(length, charset)
		JSONResponse(w, Response{Result: result})
	})
	/* /scan endpoint */
	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		address := r.PostFormValue("address")
		portLow, err := strconv.Atoi(r.PostFormValue("portLow"))
		if err != nil {
			return
		}
		portHigh, err := strconv.Atoi(r.PostFormValue("portHigh"))
		if err != nil {
			return
		}
		timeout, err := strconv.Atoi(r.PostFormValue("timeout"))
		if err != nil {
			return
		}
		openPorts, err := ScanPortRange(address, portLow, portHigh, timeout)
		if err != nil {
			JSONResponse(w, Response{Error: err.Error()})
			return
		}
		JSONResponse(w, Response{Result: openPorts})
	})
	/* /timeresponses endpoint */
	http.HandleFunc("/timeresponses", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		address := r.PostFormValue("address")
		if !strings.Contains(address, "http") {
			address = fmt.Sprintf("https://%v", address)
		}
		response, err := ResponseTime(address)
		if err != nil {
			JSONResponse(w, Response{Error: err.Error()})
			return
		}
		JSONResponse(w, Response{Result: response})
	})
	/* /resolve endpoint */
	http.HandleFunc("/resolve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		address := r.PostFormValue("address")
		response, err := Resolve(address)
		if err != nil {
			JSONResponse(w, Response{Error: err.Error()})
			return
		}
		JSONResponse(w, Response{Result: response})
	})
	/* /exif endpoint */
	http.HandleFunc("/exif", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		//mode := r.PostFormValue("mode")
		files := r.PostFormValue("files")
		log.Println(files)
		JSONResponse(w, Response{Result: files})
	})
	/* Start server */
	log.Printf("Starting on port %v\n", *port)
	if *verbose {
		http.ListenAndServe(":"+*port, handlers.LoggingHandler(os.Stdout, http.DefaultServeMux))
	} else {
		http.ListenAndServe(":"+*port, nil)
	}
}

// JSONResponse crafts a JSON response and writes it to a http.ResponseWriter header
func JSONResponse(w http.ResponseWriter, x interface{}) {
	bytes, err := json.Marshal(x)
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(bytes)
}

// Hash hashes data to algorithm.
func Hash(data, algorithm string) (string, error) {
	var h hash.Hash
	var err error
	dataAsBytes := []byte(data)
	switch algorithm {
	case "MD5":
		h = md5.New()
	case "MD4":
		h = md4.New()
	case "SHA1":
		h = sha1.New()
	case "SHA2-224":
		h = sha256.New224()
	case "SHA2-256":
		h = sha256.New()
	case "SHA2-384":
		h = sha512.New384()
	case "SHA2-512":
		h = sha512.New()
	case "SHA3-224":
		h = sha3.New224()
	case "SHA3-256":
		h = sha3.New256()
	case "SHA3-384":
		h = sha3.New384()
	case "SHA3-512":
		h = sha3.New512()
	case "Blake2b-256":
		h, err = blake2b.New256(nil)
	case "Blake2b-384":
		h, err = blake2b.New384(nil)
	case "Blake2b-512":
		h, err = blake2b.New512(nil)
	case "Blake2s-256":
		h, err = blake2s.New256(nil)
	}
	if err != nil {
		return "", err
	}
	h.Write(dataAsBytes)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Generate generates a string with a defined length and charset.
func Generate(length int, charset string) string {
	chars := []rune(charset)
	/* It's pseudo-RNG but also who cares */
	rand.Seed(time.Now().UnixNano())
	bytes := make([]rune, length)
	for i := range bytes {
		bytes[i] = chars[rand.Intn(len(chars))]
	}
	return string(bytes)
}

var (
	openPorts []int
	scanErr   error
	result    string
)

// PortScanner holds some important data for the port scanning process, like a mutex,
// lock, and the ip being scanned.
type PortScanner struct {
	mu   sync.Mutex
	ip   string
	lock *semaphore.Weighted
}

// Start aquires a lock and scans a port.
func (ps *PortScanner) Start(f, l, timeout int, wg *sync.WaitGroup) {
	for port := f; port <= l; port++ {
		wg.Add(1)
		ps.lock.Acquire(context.TODO(), 1)
		go func(port int) {
			defer ps.lock.Release(1)
			ScanPort(ps.ip, port, timeout, wg)
		}(port)
	}
}

// ScanPortRange is the function most directly called by the web interface.
// it creates an instance of the portscannner struct and uses it to create
// a work group for each ip being scanned.
func ScanPortRange(address string, minPort, maxPort, timeout int) (string, error) {
	ps := &PortScanner{
		ip:   address,
		lock: semaphore.NewWeighted(500),
	}
	var wg sync.WaitGroup
	ps.Start(minPort, maxPort, timeout, &wg)
	wg.Wait()
	var openPortsArray []string
	for i := 0; i < len(openPorts); i++ {
		openPortsArray = append(openPortsArray, fmt.Sprintf("%v", openPorts[i]))
	}
	result = strings.Join(openPortsArray, ", ")
	if strings.TrimSpace(result) == "" {
		result = "nil"
	}
	openPorts = []int{}
	return result, scanErr
}

// ScanPort actually scans a port. If too many are being scanned at once, it waits.
func ScanPort(address string, port, timeout int, wg *sync.WaitGroup) {
	defer wg.Done()
	target := fmt.Sprintf("%s:%d", address, port)
	connection, err := net.DialTimeout("tcp", target, time.Duration(timeout)*time.Millisecond)
	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(1 * time.Second)
			ScanPort(address, port, timeout, wg)
		} else if strings.Contains(err.Error(), "no such host") {
			scanErr = err
		}
		return
	}
	connection.Close()
	openPorts = append(openPorts, port)
}

// Resolve resolves an IP to a URL or a URL to an IP(s)
func Resolve(address string) (string, error) {
	var (
		resolved []string
		err      error
	)
	if net.ParseIP(address) != nil {
		resolved, err = net.LookupAddr(address)
	} else {
		resolved, err = net.LookupHost(address)
	}
	return strings.TrimRight(strings.Join(resolved, ", "), "."), err
}

// ResponseTime times how long it takes for an address to respond
func ResponseTime(address string) (string, error) {
	var (
		start, dns, tlsHandshake time.Time
	)
	var result strings.Builder
	req, err := http.NewRequest("GET", address, nil)

	trace := &httptrace.ClientTrace{
		DNSStart: func(dsi httptrace.DNSStartInfo) {
			dns = time.Now()
		},
		DNSDone: func(ddi httptrace.DNSDoneInfo) {
			result.WriteString(fmt.Sprintf("DNS: %v\n", time.Since(dns)))
		},
		TLSHandshakeStart: func() {
			tlsHandshake = time.Now()
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			result.WriteString(fmt.Sprintf("Handshake: %v\n",
				time.Since(tlsHandshake)))
		},
		GotFirstResponseByte: func() {
			result.WriteString(fmt.Sprintf("First byte: %v\n", time.Since(start)))
		},
	}
	/*
	 * Connect to the specified address and time it
	 */
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	start = time.Now()
	_, err = http.DefaultTransport.RoundTrip(req)
	result.WriteString(fmt.Sprintf("Total: %v\n", time.Since(start)))
	return result.String(), err
} /* https://stackoverflow.com/questions/48077098/ */

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/imkira/gcp-iap-auth/jwt"
	"google.golang.org/api/idtoken"
)

type proxy struct {
	backend             *url.URL
	audiences           string
	emailHeader         string
	authorizationHeader string
	proxy               *httputil.ReverseProxy
}

func newProxy(backendURL, audiences string, authorizationHeader string, emailHeader string) (*proxy, error) {
	backend, err := url.Parse(backendURL)
	if err != nil {
		return nil, fmt.Errorf("Could not parse URL '%s': %s", backendURL, err)
	}
	return &proxy{
		backend:             backend,
		audiences:           audiences,
		emailHeader:         emailHeader,
		authorizationHeader: authorizationHeader,
		proxy:               httputil.NewSingleHostReverseProxy(backend),
	}, nil
}

func (p *proxy) handler(res http.ResponseWriter, req *http.Request) {
	claims, err := jwt.RequestClaims(req, cfg)
	if err != nil {
		if claims == nil || len(claims.Email) == 0 {
			log.Printf("Failed to authenticate (%v)\n", err)
		} else {
			log.Printf("Failed to authenticate %q (%v)\n", claims.Email, err)
		}
		http.Error(res, "Unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := context.Background()
	audience := *audiences
	ts, err := idtoken.NewTokenSource(ctx, audience)
	if err != nil {
		log.Printf("Failed to authorize (%v)\n", err)
		http.Error(res, "Forbidden", http.StatusForbidden)
		return
	}

	token, err := ts.Token()
	if err != nil {
		log.Printf("Failed to retrieve idToken (%v)\n", err)
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if p.authorizationHeader != "" {
		req.Header.Set(p.authorizationHeader, token.AccessToken)
	} else {
		token.SetAuthHeader(req)
	}

	if p.emailHeader != "" {
		req.Header.Set(p.emailHeader, claims.Email)
	}
	p.proxy.ServeHTTP(res, req)
}

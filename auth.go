package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/imkira/gcp-iap-auth/jwt"
	"google.golang.org/api/idtoken"
)

type userIdentity struct {
	Subject string `json:"sub,omitempty"`
	Email   string `json:"email,omitempty"`
}

func authHandler(res http.ResponseWriter, req *http.Request) {
	claims, err := jwt.RequestClaims(req, cfg)
	if err != nil {
		if claims == nil || len(claims.Email) == 0 {
			log.Printf("Failed to authenticate (%v)\n", err)
		} else {
			log.Printf("Failed to authenticate %q (%v)\n", claims.Email, err)
		}
		res.WriteHeader(http.StatusUnauthorized)
		return
	}
	user := &userIdentity{
		Subject: claims.Subject,
		Email:   claims.Email,
	}
	res.Header().Add("email", user.Email)
	res.Header().Add("subject", user.Subject)
	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
	log.Printf("Authenticated %q (token expires at %v)\n", user.Email, expiresAt)
	res.WriteHeader(http.StatusOK)
	json.NewEncoder(res).Encode(user)

	ctx := context.Background()
	audience := *audiences
	ts, err := idtoken.NewTokenSource(ctx, audience)
	if err != nil {
		log.Printf("Failed to authorize (%v)\n", err)
		http.Error(res, "Forbidden", http.StatusForbidden)
		return
	}
	log.Printf("Authorization config retrieved\n")

	token, err := ts.Token()
	if err != nil {
		log.Printf("Failed to retrieve idToken (%v)\n", err)
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Printf("Authorization token retrieved successfully\n")

	token.SetAuthHeader(req)

	log.Printf("Authorization token header set: %s\n", token.AccessToken)

	log.Printf("Headers in request:\n")

	// Loop over header names
	for name, values := range req.Header {
		// Loop over all values for the name.
		for _, value := range values {
			log.Printf(name, value)
		}
	}

}

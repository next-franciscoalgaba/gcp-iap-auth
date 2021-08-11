package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/imkira/gcp-iap-auth/jwt"
	"google.golang.org/api/idtoken"
)

func resolveCloudRunHost(projectHash string) (string, error) {
	// Request may be coming from domain in LB
	// Get Cloud Run service name from env K_SERVICE set by GCP
	svc, exists := os.LookupEnv("K_SERVICE")
	if !exists || svc == "" {
		svc = "iap-auth-service"
	}
	log.Printf("service name: %s", svc)

	region, err := regionFromMetadata()
	if err != nil {
		return "", fmt.Errorf("[proxy] failed to infer region from metadata service: %v", err)
	}

	log.Printf("region response=%s", region)
	rc, ok := cloudRunRegionCodes[region]
	if !ok {
		return "", fmt.Errorf("region %q is not handled", region)
	}

	return mkCloudRunHost(svc, rc, projectHash), nil

}

func mkCloudRunHost(svc, regionCode, projectHash string) string {
	return fmt.Sprintf("%s-%s-%s.a.run.app", svc, projectHash, regionCode)
}

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
	ts, err := idtoken.NewTokenSource(ctx, os.Getenv("TARGET_SERVICE_URL"))
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

	// projectHash := os.Getenv("CLOUD_RUN_PROJECT_HASH")
	// host, err := resolveCloudRunHost(projectHash)
	if err != nil {
		log.Printf("Failed to retrieve host (%v)\n", err)
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	host := os.Getenv("TARGET_SERVICE_URL")
	req.Header.Set("Host", host)
	req.Host = host
	req.URL.Host = host
	req.URL.Scheme = "https"

	log.Printf("Host header set: %s\n", host)

	log.Printf("Headers in request:\n")

	// Loop over header names
	for name, values := range req.Header {
		// Loop over all values for the name.
		for _, value := range values {
			log.Printf(name, value)
		}
	}

}

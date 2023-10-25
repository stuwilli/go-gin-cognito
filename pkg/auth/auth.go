package auth

import (
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"log"
	"time"
)

type CognitoAuth struct {
	// Confidential fields
	Region     string
	UserPoolID string
	JWKSetUrl  string
	JWK        jwk.Set
}

func NewCognitoAuth(region, userPoolID string) *CognitoAuth {

	url := "https://cognito-idp." + region + ".amazonaws.com/" + userPoolID + "/.well-known/jwks.json"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Create a new cache
	cache := jwk.NewCache(ctx)
	// Register the cache to the default registry
	_ = cache.Register(url, jwk.WithMinRefreshInterval(15*time.Minute))
	// Fetch the JWKs from the remote server
	_, err := cache.Refresh(ctx, url)

	if err != nil {
		log.Printf("Failed to refresh google JWKS: %s", err)
		return nil
	}
	// Create a JWK Set for the given URL
	set := jwk.NewCachedSet(cache, url)

	return &CognitoAuth{
		Region:     region,
		UserPoolID: userPoolID,
		JWKSetUrl:  url,
		JWK:        set,
	}
}

// ValidateToken validates a token and returns true if the token is valid
// and false if the token is invalid.
// If the token is invalid, an error is returned.
func (a *CognitoAuth) ValidateToken(token string, requiredGroups ...string) (bool, error) {
	parsedToken, err := jwt.ParseString(token, jwt.WithKeySet(a.JWK), jwt.WithAcceptableSkew(1*time.Second),
		jwt.WithValidate(true))

	if err != nil {
		return false, errors.New("invalid token")
	}

	if len(requiredGroups) > 0 {
		return validateRequiredGroups(parsedToken, requiredGroups)
	}

	return true, nil
}

// validateRequiredGroups validates that the user belongs to the required groups
func validateRequiredGroups(parsedToken jwt.Token, requiredGroups []string) (bool, error) {
	tokenUse, ok := parsedToken.Get("token_use")
	if !ok {
		return false, errors.New("missing token_use claim")
	}
	// Check if the token is an access token
	if tokenUseStr, ok := tokenUse.(string); !ok || tokenUseStr != "access" {
		return false, errors.New("not an access token")
	}
	// Get the Cognito groups from the token
	groupsInterface, ok := parsedToken.Get("cognito:groups")
	if !ok {
		return false, errors.New("missing groups claim")
	}

	// Convert the interface to a slice of strings
	groups := groupsInterface.([]interface{})
	// Check if the user belongs to the required groups
	if !containsGroup(groups, requiredGroups) {
		return false, errors.New("user does not belong to the appropriate group")
	}

	return true, nil
}

// containsGroup checks if the token groups contain one of the required groups
func containsGroup(tokenGroups []interface{}, requiredGroups []string) bool {
	for _, requiredGroup := range requiredGroups {
		for _, tokenGroup := range tokenGroups {
			if tokenGroup.(string) == requiredGroup {
				// One of the required groups is in the token groups
				return true
			}
		}
	}
	return false
}

// CognitoMiddleware is a Gin middleware that checks if the user is authenticated
func (a *CognitoAuth) CognitoMiddleware(groups ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		result, err := a.ValidateToken(authHeader, groups...)
		if err != nil || !result {
			c.AbortWithStatus(401)
			return
		}
		c.Next()
	}
}

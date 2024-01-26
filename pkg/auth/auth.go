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

func NewCognitoAuth(region, userPoolID string) (*CognitoAuth, error) {

	url := "https://cognito-idp." + region + ".amazonaws.com/" + userPoolID + "/.well-known/jwks.json"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Create a new cache
	cache := jwk.NewCache(ctx)
	// Register the cache to the default registry
	err := cache.Register(url, jwk.WithMinRefreshInterval(15*time.Minute))

	if err != nil {
		log.Printf("JWKS URL could not be registered: %s", err)
		return nil, err
	}

	// Fetch the JWKs from the remote server
	_, err = cache.Refresh(ctx, url)

	if err != nil {
		log.Printf("Failed to refresh google JWKS: %s", err)
		return nil, err
	}
	// Create a JWK Set for the given URL
	set := jwk.NewCachedSet(cache, url)

	return &CognitoAuth{
		Region:     region,
		UserPoolID: userPoolID,
		JWKSetUrl:  url,
		JWK:        set,
	}, nil
}

// ValidateToken validates a token and returns true if the token is valid
// and false if the token is invalid.
// If the token is invalid, an error is returned.
func (a *CognitoAuth) ValidateToken(token string, requiredGroups ...string) (jwt.Token, error) {
	parsedToken, err := jwt.ParseString(token, jwt.WithKeySet(a.JWK), jwt.WithAcceptableSkew(1*time.Second),
		jwt.WithValidate(true))

	if err != nil {
		return nil, errors.New("invalid token")
	}

	if len(requiredGroups) > 0 {
		return validateRequiredGroups(parsedToken, requiredGroups)
	}

	return parsedToken, nil
}

// validateRequiredGroups validates that the user belongs to the required groups
func validateRequiredGroups(parsedToken jwt.Token, requiredGroups []string) (jwt.Token, error) {
	tokenUse, ok := parsedToken.Get("token_use")
	if !ok {
		return nil, errors.New("missing token_use claim")
	}
	// Check if the token is an access token
	if tokenUseStr, ok := tokenUse.(string); !ok || tokenUseStr != "access" {
		return nil, errors.New("not an access token")
	}
	// Get the Cognito groups from the token
	groupsInterface, ok := parsedToken.Get("cognito:groups")
	if !ok {
		return nil, errors.New("missing groups claim")
	}

	// Convert the interface to a slice of strings
	groups := groupsInterface.([]interface{})
	// Check if the user belongs to the required groups
	if !containsGroup(groups, requiredGroups) {
		return nil, errors.New("user does not belong to the appropriate group")
	}

	return parsedToken, nil
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

// parseBearerToken parses the bearer token from the Authorization header
func parseBearerToken(authHeader string) (string, error) {
	if len(authHeader) < 8 {
		return "", errors.New("invalid authorization header")
	}

	if authHeader[:7] != "Bearer " {
		return "", errors.New("invalid authorization header")
	}

	return authHeader[7:], nil
}

// CognitoMiddleware is a Gin middleware that checks if the user is authenticated
func (a *CognitoAuth) CognitoMiddleware(groups ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		token, err := parseBearerToken(authHeader)
		if err != nil {
			log.Printf("Error parsing bearer token: %s", err)
			c.AbortWithStatus(401)
			return
		}
		result, err := a.ValidateToken(token, groups...)
		if err != nil || result == nil {
			log.Printf("Error validating token: %s", err)
			c.AbortWithStatus(401)
			return
		}
		cognitoUser, _ := result.Get("username")
		c.Set("jwt_token", token)
		c.Set("cognito_user", cognitoUser)
		c.Next()
	}
}

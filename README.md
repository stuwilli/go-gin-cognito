# Go Gin Cognito JWT Auth Middleware

```go
package main

import (
	"github.com/gin-gonic/gin"
	"go-gin-cognito/pkg/auth"
)

const (
	// CognitoRegion is the AWS region where your user pool is deployed
    CognitoRegion = ""
	// CognitoUserPoolID is the ID of your user pool
	CognitoUserPoolID = ""
)

func main() {
	// Create a Gin router
	r := gin.Default()
	// Initiate Cognito Auth
	cognito := NewCognitoAuth(CognitoRegion, CognitoUserPoolID)
	// Add the middleware to your router
	r.Use(cognito.CognitoMiddleware("admin", "trafficker"))
	// Define your routes
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Hello.",
		})
	})
	// Add more routes as needed
	// Start the server
	err := r.Run(":8080")
	if err != nil {
		return
	}
}
```
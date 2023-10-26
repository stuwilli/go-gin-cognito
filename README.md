# Go Gin Cognito JWT Auth Middleware

### Testing
There is a basic test suite which requires some environment variables to be set. You can set them in a `.env` file in the root of the project. The following variables are required:

```bash
AWS_REGION=
AWS_COGNITO_POOL_ID=
AWS_COGNITO_CLIENT_ID=
TEST_COGNITO_USERNAME=
TEST_COGNITO_PASSWORD=
```

### Example Usage

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
package test

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/joho/godotenv"
	"go-gin-cognito/pkg/auth"
	"os"
	"testing"
)

func init() {
	err := godotenv.Load("../.env")
	fmt.Println(os.Getenv("AWS_REGION"))
	if err != nil {
		panic("Error loading .env file")
	}
}

var (
	//Invalid token
	invalidToken = "eyJraWQiOiJZY00yc3RpV21jN284SW5PcTlcL1pBckFxMkJzYlwveWUxbTE1Vmx3b3dZNXc9IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI1MjQxYzcxYS01NTdhLTQxNzMtYTRjOC0yNjgwYzk4YjdlMmQiLCJjb2duaXRvOmdyb3VwcyI6WyJ0cmFmZmlja2VyIl0sImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5ldS13ZXN0LTEuYW1hem9uYXdzLmNvbVwvZXUtd2VzdC0xX3h4UjlsOWs4MiIsInZlcnNpb24iOjIsImNsaWVudF9pZCI6IjFvZW40amNidXNlYjR1NHFvdXA2ZWY0N21lIiwib3JpZ2luX2p0aSI6ImRjZjIxZGIwLTNiZDQtNGI1MS04YWY5LTEzOTMzYTMxMTg1YiIsImV2ZW50X2lkIjoiZTcyZWVlNTktZTdhYi00N2UxLTk0OGYtMGFmNGIxOWVkNmM2IiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiBvcGVuaWQgcHJvZmlsZSBlbWFpbCIsImF1dGhfdGltZSI6MTY5ODA5NjgzOCwiZXhwIjoxNjk4MTAwNDM4LCJpYXQiOjE2OTgwOTY4MzgsImp0aSI6ImE1MGRkMmIzLTM2MjQtNDMwNi05Y2E4LTU3NjkyMTI1MzVkMyIsInVzZXJuYW1lIjoiNTI0MWM3MWEtNTU3YS00MTczLWE0YzgtMjY4MGM5OGI3ZTJkIn0.LVHqnVGGRHwxH2_bzCNMEqUgD3RJK3jVZQdf6zR7vWATGo_yn-2KsGfhqoX1N8gk0MoJMKkReI1Km0iOmbIVf_evZxLhsTqtCHVIMhi0zyRtxEr5SumiDMyz7_xlrhF6osD-7WhV_jZHJA0laTixIZkHQa8b0PWLeimGS3yFyHV5Us8lcZ5KE2EEhQQ4f4l6-5KXvCL1gqiD8OgqQThb9ZolyyrY9KVYP_6TWITk22SgyLhT4iaH1mu6YmtuUMme1TR6R-ldxctxdusT_NYgF1s50f28R0GiTR8UgVnXaQMXyF5Hp8fNuP8p6mwiP-rGMz7tSQ2KJmzOLlr7pK3EzQ"
)

func getToken() string {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(os.Getenv("AWS_REGION")), // e.g., "us-west-2"
	})

	if err != nil {
		fmt.Println(err)
		return ""
	}

	svc := cognitoidentityprovider.New(sess)

	params := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: aws.String("USER_PASSWORD_AUTH"),               // Required
		ClientId: aws.String(os.Getenv("AWS_COGNITO_CLIENT_ID")), // Required
		AuthParameters: map[string]*string{ //Required
			"USERNAME": aws.String(os.Getenv("TEST_COGNITO_USERNAME")),
			"PASSWORD": aws.String(os.Getenv("TEST_COGNITO_PASSWORD")),
		},
	}

	resp, err := svc.InitiateAuth(params)

	if err != nil {
		fmt.Println(err.Error())
		return ""
	}

	return *resp.AuthenticationResult.AccessToken
}

func TestValidateToken(t *testing.T) {

	t.Run("should return true with no error", func(t *testing.T) {
		// Initiate your struct
		a, _ := auth.NewCognitoAuth(os.Getenv("AWS_REGION"), os.Getenv("AWS_COGNITO_POOL_ID"))
		// Use a valid token, this is a mock token, replace with a real one for testing
		ok, err := a.ValidateToken(getToken(), "trafficker")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if !ok {
			t.Errorf("Expected token to be valid, but got false")
		}
	})

	t.Run("should return false with an error", func(t *testing.T) {
		// Initiate your struct
		a, _ := auth.NewCognitoAuth(os.Getenv("AWS_REGION"), os.Getenv("AWS_COGNITO_POOL_ID"))

		// Invalid token
		ok, err := a.ValidateToken(invalidToken)
		if err == nil {
			t.Errorf("Expected error, but got none")
		}
		if ok {
			t.Errorf("Expected token to be invalid, but got true")
		}
	})
}

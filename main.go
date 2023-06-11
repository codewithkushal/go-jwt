package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var jwtKey = []byte("your_secret_key")

type Claims struct {
	// this username should be loaded from database so a unique username can be used it can be either email or username or which ever is unique
	Username string `json:"username"`
	jwt.StandardClaims
}

func main() {
	router := gin.Default()

	// Route handler for generating a JWT token
	router.POST("/token", func(c *gin.Context) {
		// You can implement your own logic to authenticate the user and generate a token
		// In this example, we'll use a static username for simplicity
		claims := &Claims{
			Username: "example_user",
			StandardClaims: jwt.StandardClaims{
				// add 24 hrs to current time
				// Token expires in 24 hours
				ExpiresAt: time.Now().Add(time.Second * 10).Unix(),
			},
		}

		// Declare the token with the algorithm used for signing, and the claims
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		// Create the JWT string and store it in the response object and also database - this is the token that will be used for authentication
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// Return the token to the client
		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	})

	// Apply the authMiddleware to protected routes
	router.Use(authMiddleware())

	// Protected route
	router.GET("/protected", func(c *gin.Context) {
		// Access the claims from the context
		claims, _ := c.Get("claims")
		c.JSON(http.StatusOK, gin.H{"message": "You've accessed the protected route!", "claims": claims})
	})

	// Start the server
	router.Run(":8080")
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authorizationHeader := c.GetHeader("Authorization")
		if authorizationHeader == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		tokenString := strings.Replace(authorizationHeader, "Bearer ", "", 1)
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// Set the claims in the context for later use
		claims, ok := token.Claims.(*Claims)
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("claims", claims)

		// If the token is valid, proceed to the next handler
		c.Next()
	}
}

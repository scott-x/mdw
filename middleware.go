package mdw

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"

	"github.com/scott-x/mdw/utils"
	"github.com/scott-x/resp"
)

var (
	headerName string //http request header that jwt token is set to, default is "token"
	secret     []byte //will create a new one if not set
	expire     int64  //expire time - unit => second, default value 1 day
)

func SetSecret(str string) {
	secret = []byte(str)
}

func SetJWTExpire(i int64) {
	expire = i
}

func getJWTExpire() int64 {
	if expire == 0 {
		expire = 60 * 60 * 24 //default: 1 day
	}
	return expire
}

func getSecret() []byte {
	if len(string(secret)) == 0 {
		return []byte(utils.InitServerSecret())
	}
	return secret
}

func getHeaderName() string {
	if len(headerName) == 0 {
		return "token"
	}
	return headerName
}

func SetHeaderName(str string) {
	headerName = str
}

func AllowCrossOrigin() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method

		//c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Origin", c.GetHeader("Origin"))
		//fmt.Println(c.GetHeader("Origin"))
		c.Header("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", fmt.Sprintf("Content-Type, Content-Length, X-Requested-With, %s", utils.FixHeaderKey(getHeaderName()))) //X-Requested-With: image upload
		c.Header("Access-Control-Expose-Headers", "Access-Control-Allow-Headers, Token")
		c.Header("Access-Control-Allow-Credentials", "true")

		if method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// AuthRequired jwt
func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		r, _ := c.Request, c.Writer
		//h := r.Header
		//for k, v := range h {
		//	fmt.Printf("(k,v)==>(%s,%s)", k, v)
		//
		//}
		//fmt.Println("global.Token.Name:", global.Token.Name)

		//get jwt token from header
		tokenCookie := r.Header.Get(utils.FixHeaderKey(getHeaderName()))

		if len(tokenCookie) == 0 {
			resp.ErrorNotAuthorized(c)
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenCookie, func(t *jwt.Token) (interface{}, error) {
			_, ok := t.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				resp.ErrorNotAuthorized(c)
				c.Abort()
			}
			return getSecret(), nil
		})

		if err != nil {
			resp.ErrorNotAuthorized(c)
			c.Abort()
		}

		if token.Valid {
			//do sth
			//https: //stackoverflow.com/questions/45405626/how-to-decode-a-jwt-token-in-go
			claims, _ := token.Claims.(jwt.MapClaims)
			// claims are actually a map[string]interface{}
			//fmt.Println(claims)
			//set uid to gin.Context
			if uid, ok := claims["uid"]; ok {
				c.Set("uid", uid)
			}
			c.Next()
		}
	}
}

// any to int: https://stackoverflow.com/questions/18041334/convert-interface-to-int
func GetUid(c *gin.Context) int {
	uid, _ := c.Get("uid")
	return int(uid.(float64))
}

// create jwt token with user id
func CreateJWT(uid int) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	//jwt token expire time
	claims["exp"] = time.Now().Add(time.Second * time.Duration(getJWTExpire())).Unix()
	//set uid
	claims["uid"] = uid

	tokenStr, err := token.SignedString(getSecret())
	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

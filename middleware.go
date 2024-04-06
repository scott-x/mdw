package mdw

import (
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"

	"github.com/scott-x/mdw/utils"
	"github.com/scott-x/resp"
)

var (
	headerName, secret string
)

func SetSecret(str string) {
	secret = str
}

func getSecret() string {
	if len(secret) == 0 {
		return utils.InitServerSecret()
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
		// 必须，接受指定域的请求，可以使用*不加以限制，但不安全
		//c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Origin", c.GetHeader("Origin"))
		fmt.Println(c.GetHeader("Origin"))
		// 必须，设置服务器支持的所有跨域请求的方法
		c.Header("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, OPTIONS")
		// 服务器支持的所有头信息字段，不限于浏览器在"预检"中请求的字段
		c.Header("Access-Control-Allow-Headers", fmt.Sprintf("Content-Type, Content-Length, X-Requested-With, %s", utils.FixHeaderKey(getHeaderName()))) //X-Requested-With 图片上传
		// 可选，设置XMLHttpRequest的响应对象能拿到的额外字段
		c.Header("Access-Control-Expose-Headers", "Access-Control-Allow-Headers, Token")
		// 可选，是否允许后续请求携带认证信息Cookie，该值只能是true，不需要则不设置
		c.Header("Access-Control-Allow-Credentials", "true")
		// 放行所有OPTIONS方法
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
			c.Next()
		}
	}
}

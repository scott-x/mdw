package main

import (
	"github.com/gin-gonic/gin"
	"github.com/scott-x/mdw"
	"github.com/scott-x/resp"
	"log"
)

func main() {
	mdw.SetSecret("balabala..")
	//mdw.SetHeaderName("xxx")
	mdw.SetJWTExpire(20) //20 seconds
	route := gin.Default()
	route.Use(mdw.AllowCrossOrigin())
	auth := route.Group("/auth")
	auth.Use(mdw.AuthRequired())

	auth.GET("/test", func(c *gin.Context) {
		type Output struct {
			Name string `json:"name"`
			Age  int    `json:"age"`
		}
		log.Println("uid:", mdw.GetUid(c))
		o := Output{
			Name: "Scott",
			Age:  18,
		}
		resp.Success(c, o)
	})

	route.POST("/login", func(c *gin.Context) {
		type User struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		var u User
		if err := c.ShouldBind(&u); err != nil {
			resp.ErrorBadRequest(c)
			return
		}
		type Output struct {
			Token string `json:"token"`
		}

		if u.Username == "" || u.Password == "" {
			resp.Error(c, 2001, "用户名或密码不能为空")
			return
		}

		if u.Username == "scott" && u.Password == "123" {
			//success
			token, err := mdw.CreateJWT(1)
			log.Println(token)
			if err != nil {
				log.Println(err)
				resp.Error(c, 2002, "token生成失败")
				return
			}
			output := Output{Token: token}
			resp.Success(c, output)
			return
		}

		resp.Error(c, 2001, "用户名或密码错误")

	})

	route.GET("/test1", func(c *gin.Context) {
		resp.Success(c, "success")
	})

	route.GET("/test2", func(c *gin.Context) {
		resp.ErrorBadRequest(c)
	})

	route.GET("/test3", func(c *gin.Context) {
		resp.ErrorNotAuthorized(c)
	})

	route.GET("/test4", func(c *gin.Context) {
		resp.Error(c, 2004, "username, password does not match")
	})

	err := route.Run(":8989")
	if err != nil {
		return
	}
}

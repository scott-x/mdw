# mdw
gin middleware

### note

Before using the middleware, please remember to init `headerName` `secret` & `expire`.

Here is the example:

```go
    mdw.SetSecret("balabala..")
	mdw.SetHeaderName("xxx")
	mdw.SetJWTExpire(20) //20 seconds
```

Full example can be seen [here](./example/main.go)
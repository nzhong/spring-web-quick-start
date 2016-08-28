SPRING WEB QUICKSTART
=====================

This repo contains seven simple sub-projects, <b>one</b>, <b>two</b>, <b>three</b>, <b>four</b>, <b>five</b>, <b>six</b>, and <b>seven</b>. Each one is built on top of the previous one, and add just a little bit of code:

- <b>one</b>: a minimal web servlet handler, with just <a href="http://www.eclipse.org/jetty/">Jetty</a>. No Spring. We can answer servlet requests now.
- <b>two</b>: Jetty from <b>one</b>, and by loading <a href="http://spring.io/">Spring</a> 's WebApplicationInitializer upon start-up, load the SpringCore and SpringWeb into the project. We now have a full REST server.
- <b>three</b>: Built on top of <b>two</b>, and add Spring Security. Now we can see that certain endpoints requires authentication.
- <b>four</b>: Based on <b>three</b>, with spring-data-mongodb integrated. We can now save and read Java objects from the database (to run this sub-project, you need a local mongodb instance running on localhost:27017).
- <b>five</b>: Now that we have a database backend, we can do some real password authentications.
- <b>six</b>: use JWT token based authentication to replace Cookie based sessions.
- <b>seven</b>: Okta/SAML integration.

# one

This is just a simple 'embedded-jetty' java application, listenning on port 9001, with one servlet handler for the path "/serv"

```
> mvn clean package
> java -jar one/target/one-1.0-SNAPSHOT.jar

then load in your browser, http://127.0.0.1:9001/serv
you should see 'JettyServer'
```

# two

In this project, we start 'embedded-jetty' similarly to one, and again attach the same servlet handler to the path "/serv". By loading spring's WebApplicationInitializer and attaching spring's DispatcherServlet to the path "/spring/\*", anything under "/spring/" will be handled by DispatcherServlet and further handled by our REST controllers.

```
> mvn clean package
> java -jar two/target/two-1.0-SNAPSHOT.jar

in your browser load http://127.0.0.1:9002/serv
you should see 'JettySpringServer'. (this is handled by our non-spring servlet)

load http://127.0.0.1:9002/spring/status
you should see 'ok'. (this is handled by our spring REST controller)
```


# three

Here we added a SecurityConfig class, which specifies that "/spring/**" will require authentication.

```
> mvn clean package
> java -jar three/target/three-1.0-SNAPSHOT.jar

in your browser load http://127.0.0.1:9003/serv
you should see 'JettySpringServer'. (this is handled by our non-spring servlet)

load http://127.0.0.1:9003/spring/status
you should see the browser is redirected to /login
```

# four

<b>To run this sub-project, you need a local mongodb instance running on localhost:27017</b>

In this project we disabled the authentication on "/spring/**", and added spring-data-mongodb. Then we added a provision class and a corresponding repository class. Then in the REST controller, the repo and a mongodb connection can be autowired in, and the Java provision class can be read/write into the database.

```
> mvn clean package
> java -jar four/target/four-1.0-SNAPSHOT.jar

in your browser load http://127.0.0.1:9004/serv
you should see 'JettySpringServer'. (this is handled by our non-spring servlet)

load http://127.0.0.1:9004/spring/status
you should see 'ok'. (this is handled by our spring REST controller)

load http://127.0.0.1:9004/spring/read
you should see an empty page.

load http://127.0.0.1:9004/spring/seed
you should see ok. But a customer record would have been seeded into the database.

load http://127.0.0.1:9004/spring/read again, and you should see
{
  "id": "57be49bc8dee2a6f59e6cecf",
  "firstName": "Jack",
  "lastName": "Bauer",
  "relatives": [
    "A", "B", "Z"
  ],
  "complex": {
    "1": ["1a", "1b"],
    "2": ["2a", "2c"],
    "3": ["3x", "3z"]
  }
}
```

# five

<b>Similar to four, to run this sub-project, you need a local mongodb instance running on localhost:27017</b>

In this project we turned authentication on "/spring/\**" back on. In SecurityConfig we also wired in a LocalAuthenticationProvider, which checked username/password from the mongoDb. For this flow to work, we added AppUser/AppUserRepository class just like the Customer/CustomerRepository in four, and seeded one user (test/test) in the beginning (SecurityConfig). Finally we specified the after login success url to be "/spring/status"

```
> mvn clean package
> java -jar five/target/five-1.0-SNAPSHOT.jar

in your browser load http://127.0.0.1:9005/spring/status
you should see the login form.

try anything other than test/test, login should fail.
with test/test, page should forward to http://127.0.0.1:9005/spring/status

now try any of the three:
http://127.0.0.1:9005/spring/status
http://127.0.0.1:9005/spring/seed
http://127.0.0.1:9005/spring/read
they should all work, since this is session based, and our session is still good.

load http://127.0.0.1:9005/logout and then try the above three URLs you will see the login form again
```

# six

<b>Similar to four, to run this sub-project, you need a local mongodb instance running on localhost:27017</b>

In this project we added an AppCustomFilter just before the spring built in UsernamePasswordAuthenticationFilter. The AppCustomFilter looks for "X-AUTH-TOKEN" in the request header, and if found, figure out which user this is. We are still using the authentication system in five (LocalAuthenticationProvider), just turned the previous cookie+session to token based. For this flow to work, we did a couple of things:

- AppCustomFilter will let /login request to go through without a valid token
- Upon login success (in http.formLogin().successHandler), we invalidate sessions, and send the token for the current user back to the client
- in AppCustomFilter, if token is valid, we call a `SecurityContextHolder.getContext().setAuthentication(loginUser)` before calling the next one in chain, which is most likely UsernamePasswordAuthenticationFilter.

```
> mvn clean package
> java -jar six/target/six-1.0-SNAPSHOT.jar

in your browser load http://127.0.0.1:9006/spring/status
you should see a 'Invalid authentication' error

try http://127.0.0.1:9006/login
with test/test, you should see a long hash like string,
eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0ZXN0In0.Gw0qZV9TnQulU8732vLPTS-ydKLgiRUz1MEuWgesb0ic1NABFU5LGcWq-SE48etJnR9yxcjF9U6bHPEzOp552Q

Now load http://127.0.0.1:9006/spring/status
you should still see a 'Invalid authentication' error, because we are token based not session based now.

From a command prompt capable of curl, do a
curl --header "X-AUTH-TOKEN: eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0ZXN0In0.Gw0qZV9TnQulU8732vLPTS-ydKLgiRUz1MEuWgesb0ic1NABFU5LGcWq-SE48etJnR9yxcjF9U6bHPEzOp552Q" http://127.0.0.1:9006/spring/status
you should see a valid result.
```


# seven

Added Okta/SAML integration via Spring-Security-SAML.

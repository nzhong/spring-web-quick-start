SPRING WEB QUICKSTART
=====================

This repo contains four simple sub-projects, <b>one</b>, <b>two</b>, <b>three</b>, and <b>four</b>. Each one is built on top of the previous one, and add just a little bit of code:

- <b>one</b>: a minimal web servlet handler, with just <a href="http://www.eclipse.org/jetty/">Jetty</a>. No Spring. We can answer servlet requests now.
- <b>two</b>: Jetty from <b>one</b>, and by loading <a href="http://spring.io/">Spring</a> 's WebApplicationInitializer upon start-up, load the SpringCore and SpringWeb into the project. We now have a full REST server.
- <b>three</b>: Built on top of <b>two</b>, and add Spring Security. Now we can see that certain endpoints requires authentication.
- <b>four</b>: Based on <b>three</b>, with spring-data-mongodb integrated. We can now save and read Java objects from the database (to run this sub-project, you need a local mongodb instance running on localhost:27017).

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

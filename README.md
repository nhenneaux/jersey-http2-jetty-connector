# JAX-RS HTTP/2 example for Java **8**, 9, 10, **11**, 12 & 13
JAX-RS (Jersey implementation) HTTP/2 with TLS client and server implementation with JSON parsing using Jackson and Jetty HTTP server/client.
a new class `JettyHttp2Connector` is implemented based on the corresponding [`JettyConnector`](https://github.com/eclipse-ee4j/jersey/blob/master/connectors/jetty-connector/src/main/java/org/glassfish/jersey/jetty/connector/JettyConnectorProvider.java)  using HTTP/1.1 client 
(Inspired from the [stackoverflow answer](https://stackoverflow.com/a/40289767/1630604)).

For a connector supporting HTTP/1.1 and HTTP/2.0, you may have a look at [Jersey Java HTTP client connector](https://github.com/nhenneaux/jersey-httpclient-connector).

[![Build Status](https://travis-ci.com/nhenneaux/jersey-http2-jetty-connector.svg?branch=master)](https://travis-ci.com/nhenneaux/jersey-http2-jetty-connector)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.nhenneaux.jersey.jetty.http2/jersey-http2-jetty/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.github.nhenneaux.jersey.jetty.http2/jersey-http2-jetty)

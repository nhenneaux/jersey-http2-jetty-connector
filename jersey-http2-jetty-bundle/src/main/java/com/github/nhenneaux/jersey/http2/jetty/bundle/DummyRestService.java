package com.github.nhenneaux.jersey.http2.jetty.bundle;

import javax.ws.rs.HEAD;
import javax.ws.rs.Path;

@Path("/")
public class DummyRestService {

    @HEAD
    @Path("ping")
    public void ping() {
        // Just checking the server is listening
    }


}

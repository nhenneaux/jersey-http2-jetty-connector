package com.github.nhenneaux.jersey.http2.jetty.bundle;

import javax.ws.rs.GET;
import javax.ws.rs.HEAD;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import java.util.concurrent.TimeUnit;

@Path("/")
public class DummyRestService {

    @HEAD
    @Path("ping")
    public void ping() {
        // Just checking the server is listening
    }

    @GET
    @Path("pingWithSleep")
    public long pingWithSleep(@QueryParam("sleepTimeInMilliseconds") long sleepTimeInMilliseconds) {

        try {
            TimeUnit.MILLISECONDS.sleep(sleepTimeInMilliseconds);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
        return sleepTimeInMilliseconds;
    }


}

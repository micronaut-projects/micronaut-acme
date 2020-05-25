package io.micronaut.mock.slow

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpResponse
import io.micronaut.http.annotation.Consumes
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Head
import io.micronaut.http.annotation.Post
import io.netty.handler.ssl.util.SelfSignedCertificate

import java.time.Duration
import java.util.concurrent.atomic.AtomicInteger

@Requires(env = "test")
@Controller('/acme')
class SlowAcmeServer {

    String expires = new Date().plus(30).format("yyyy-MM-dd'T'HH:mm'Z'")
    String domain = "yourdomain.com"
    String acmeServerUrl

    SlowServerConfig slowServerConfig

    void setSlowServerConfig(SlowServerConfig config) {
        this.slowServerConfig = config
    }

    void setAcmeServerUrl(String acmeServerUrl) {
        this.acmeServerUrl = acmeServerUrl.replaceAll("/dir", "")
    }

    @Get('/dir')
    String dirGet() {
        return getDirListing()
    }

    @Post('/dir')
    String dirPost() {
        return getDirListing()
    }

    AtomicInteger requestCounter = new AtomicInteger()

    @Consumes("application/jose+json")
    @Post('/your-order')
    String yourOrder() {
        if (slowServerConfig.isSlowOrdering()) {
            doItSlowly(slowServerConfig.duration)
        }
        int requestCount = requestCounter.getAndIncrement()
        if (requestCount % 2) {
            """
            {
               "status":"valid",
               "expires":"$expires",
               "identifiers":[
                  {
                     "type":"dns",
                     "value":"$domain"
                  }
               ],
               "authorizations":[
                  "$acmeServerUrl/authz"
               ],
               "finalize":"$acmeServerUrl/finalize",
               "certificate":"$acmeServerUrl/cert"
            }
        """
        } else {
            """
            {
               "status":"ready",
               "expires": "$expires",
               "identifiers":[
                  {
                     "type":"dns",
                     "value":"doit.is-it-friday.org"
                  }
               ],
               "authorizations":[
                  "$acmeServerUrl/authz"
               ],
               "finalize":"$acmeServerUrl/finalize"
            }
        """
        }
    }

    @Consumes("application/jose+json")
    @Post('cert')
    HttpResponse<byte[]> cert() {
        HttpResponse.ok(new SelfSignedCertificate(domain).certificate().readBytes())
                .header("Content-Type", "application/pem-certificate-chain")
    }

    @Consumes("application/jose+json")
    @Post('/sign-me-up')
    HttpResponse<String> signmeup() {
        if (slowServerConfig.isSlowSignup()) {
            doItSlowly(slowServerConfig.duration)
        }
        return HttpResponse.ok(
                """{
                       "key":{
                          "kty":"RSA",
                          "n":"xxxtRGLtg0Eqtb_ZfwLegsld46EGp7MHRtK8z1kD5zto8kWozm5s_9NQ-Htlakd94pZOmpCBg6G8i8Izc3doFqSeY9P7khf0dUIbF7K6SdwmXsAYEkCE0XmSrRBCzft82yW2jNBRsaFl-gRZkJu82L4Zleee",
                          "e":"ZZAB"
                       },
                       "contact":[
                          "mailto:testing@testing.com"
                       ],
                       "initialIp":"24.456.231.199",
                       "createdAt":"2017-05-24T01:32:46Z",
                       "status":"valid"
                    }""")
                .header("Location", "$acmeServerUrl/your-account")
    }

    @Head('/nonce-plz')
    HttpResponse<String> nonce() {
        return HttpResponse.ok("nonce")
                .header("Replay-Nonce", "nonce")
    }

    @Consumes("application/jose+json")
    @Post('/finalize')
    String finalizeOrder() {
        if (slowServerConfig.isSlowOrdering()) {
            doItSlowly(slowServerConfig.duration)
        }
        "profit"
    }

    @Consumes("application/jose+json")
    @Post('/order-plz')
    HttpResponse<String> order() {
        if (slowServerConfig.isSlowOrdering()) {
            doItSlowly(slowServerConfig.duration)
        }
        return HttpResponse.ok(
                """
                {
                   "status":"ready",
                   "expires": "$expires",
                   "identifiers":[
                      {
                         "type":"dns",
                         "value": "$domain"
                      }
                   ],
                   "authorizations":[
                      "$acmeServerUrl/authz"
                   ],
                   "finalize":"$acmeServerUrl/finalize"
                }
                """)
                .header("Location", "$acmeServerUrl/your-order")
    }

    @Consumes("application/jose+json")
    @Post('/authz')
    String authz() {
        if (slowServerConfig.isSlowAuthorization()) {
            doItSlowly(slowServerConfig.duration)
        }
        return """
            {
               "identifier":{
                  "type":"dns",
                  "value": "$domain"
               },
               "status":"valid",
               "expires": "$expires",
               "challenges":[
                  {
                     "type":"tls-alpn-01",
                     "status":"valid",
                     "url":"$acmeServerUrl/challenge",
                     "token":"pzzz_Eeee-MxxxG6Ma3-hBBBBOHh-5oBEEFtE",
                     "validationRecord":[
                        {
                           "hostname": "$domain",
                           "port":"443",
                           "addressesResolved":[
                              "127.0.0.1"
                           ],
                           "addressUsed":"127.0.0.1"
                        }
                     ]
                  }
               ]
            }
        """
    }

    private String getDirListing() {
        return """
                {
                  "keyChange": "$acmeServerUrl/rollover-account-key",
                  "meta": {
                    "termsOfService": "data:text/plain,Do%20what%20thou%20wilt"
                  },
                  "newAccount": "$acmeServerUrl/sign-me-up",
                  "newNonce": "$acmeServerUrl/nonce-plz",
                  "newOrder": "$acmeServerUrl/order-plz",
                  "revokeCert": "$acmeServerUrl/revoke-cert"
                }
            """
    }

    private void doItSlowly(Duration sleepTime) {
        println ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
        println ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
        println ">>>>>>>>>>>>>>    DOING IT SLOWLY >>>>>>>>>>"
        println ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
        println ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
        Thread.sleep(sleepTime.toMillis())
    }

}

# Hello world acme
This is a simple micronaut app that has been configured 90% of the way that should help you test out an actual implementation.
It contains a single endpoint found at `/helloWorld` but the important bits can be found in [src/main/resources/application.yml](src/main/resources/application.yml).

## Steps to get up and running

### Pre-reqs
1. You have created an account with Let's Encrypt
1. You have generated a domain key
   1. acme-utils project can help with steps 1 and 2
   1. See [here](../acme-utils/README.md)
1. You have purchased a domain name and have a way to configure DNS. In the AWS example below we will use Route53.

### Build and Deploy : 
1. From inside the `hello-world-acme` project execute the following
   1. `../../gradlew build` 

### AWS only example : 
1. Launch an EC2 instance with >= java 8 installed
   1. Tested with `amzn2-ami-hvm-2.0.20190612-x86_64-gp2 (ami-00c79db59589996b9)` but anything with >= java 8 installed should work
1. Configure EC2 Security Group to allow SSH port 22 and HTTPS port 443 traffic through
   1. If using HTTP challenge also allow port 80 through
    ![Configure Security Group](docs/images/EC2_Security_Group.png)  
1. Configure Route 53 DNS to point to your EC2 public ip address
   1. First to get the IP address of your EC2 instance
   ![Obtain IPv4 IP Address for EC2 instance](docs/images/Instances__EC2_Management_Console.png)
   1. Next create a new record set in Route 53 using the public ipv4 address for your EC2 server
   ![Create A record in Route53](docs/images/Route_53_Management_Console.png)
1. scp the `hello-world-acme` jar found here `examples/hello-world-acme/build/libs/acme-example-hello-world-acme-1.0.0.BUILD-SNAPSHOT-all.jar` to your EC2 server
   1. Example command might look something like this if using the terminal
   1. `scp -i ~/aws-keypair.pem examples/hello-world-acme/build/libs/acme-example-hello-world-acme-1.0.0.BUILD-SNAPSHOT-all.jar ec2-user@ec2-52-15-231-234.us-east-2.compute.amazonaws.com:~`
1. ssh into your EC2 server  
    1. Example command might look something like this if using the terminal
    1. `ssh -i ~/aws-keypair.pem ec2-user@ec2-52-15-231-234.us-east-2.compute.amazonaws.com`
1. Setup your environment 
    1. You will need to define the following environment variables or in this case environment yaml to successfully start the application. Using environment yaml/variables keeps you from committing
    your private key into source control. Define the properties you want to override in this yaml. Usually this would be domain, account and domain key. But also could include anything else you would like to override.
    1. Create an `env.yml` file on your ec2 server
    ```
     domain: <your domain here>
     domain-key: |
       -----BEGIN RSA PRIVATE KEY-----
       <your account key here>
       -----END RSA PRIVATE KEY-----
     account-key: |
        -----BEGIN RSA PRIVATE KEY-----
        <your account key here>
        -----END RSA PRIVATE KEY-----    
    ```
1. Start the application
    1. Note this will require sudo since we are running on 80/443. This is not ideal in a production environment and some form of load balancer
    should generally be used to accept traffic on 80/443 and forward to generally 8080/8443 (default micronaut ports). 
    1. `sudo java -Dmicronaut.config.files=env.yml -Dmicronaut.environments=<challenge type [http,tls,dns]> -jar acme-example-hello-world-acme-1.0.0.BUILD-SNAPSHOT-all.jar` 
1. Celebrate
    1. You should now see something like this when you navigate to `https://<you domain name>/helloWorld`
    1. ![Secured site with Let's Encrypt certificate](docs/images/Acme_cert_micronaut.png)

### GCP example : 
//TODO

### Azure example : 
//TODO
/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package demo.hw.server;

import java.util.HashMap;
import java.util.Map;

import org.apache.cxf.interceptor.LoggingInInterceptor;
import org.apache.cxf.interceptor.LoggingOutInterceptor;
import org.apache.cxf.jaxws.JaxWsServerFactoryBean;

import demo.hw.CommonPasswordCallback;

public class Server {

    protected Server() throws Exception {

        System.out.println("Starting Server");
        HelloWorldImpl implementor = new HelloWorldImpl();
        JaxWsServerFactoryBean svrFactory = new JaxWsServerFactoryBean();
        

        Map<String, Object> properties = new HashMap<String, Object>();

        properties.put("security.callback-handler", new CommonPasswordCallback());
        properties.put("security.signature.properties","bob.properties");
        properties.put("security.encryption.username","useReqSigCert");
        
        //properties.put("ws-security.self-sign-saml-assertion", "true");
        svrFactory.setProperties(properties);
        svrFactory.setServiceClass(HelloWorld.class);
        svrFactory.setAddress("http://localhost:9000/helloWorld");
        svrFactory.setServiceBean(implementor);

//        svrFactory.getInInterceptors().add(new SamlTokenInterceptor());
        svrFactory.getInInterceptors().add(new LoggingInInterceptor());
        svrFactory.getOutInterceptors().add(new LoggingOutInterceptor());
        svrFactory.create();
    }

    public static void main(String args[]) throws Exception {
        new Server();
        System.out.println("Server ready...");

        Thread.sleep(60 * 60 * 1000);
        System.out.println("Server exiting");
        System.exit(0);
    }
}

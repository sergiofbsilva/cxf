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

package demo.hw.client;

import java.util.HashMap;
import java.util.Map;

import org.apache.cxf.interceptor.LoggingInInterceptor;
import org.apache.cxf.interceptor.LoggingOutInterceptor;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.opensaml.saml.common.xml.SAMLConstants;

import demo.hw.CommonPasswordCallback;
import demo.hw.server.HelloWorld;
import demo.hw.server.SenderVouchesSamlCallbackHandler;

public final class Client {

    private Client() {
    } 

    public static void main(String args[]) throws Exception {
        JaxWsProxyFactoryBean factory = new JaxWsProxyFactoryBean();
        factory.getInInterceptors().add(new LoggingInInterceptor());
        factory.getOutInterceptors().add(new LoggingOutInterceptor());

        factory.setAddress("http://localhost:9000/helloWorld");
        Map<String, Object> properties = new HashMap<String, Object>();

        properties.put("ws-security.callback-handler", new CommonPasswordCallback());
                
        SenderVouchesSamlCallbackHandler samlCallbackHandler = new SenderVouchesSamlCallbackHandler();
        samlCallbackHandler.setSaml2(true);
        samlCallbackHandler.setSigned(true);
        samlCallbackHandler.setConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);

        properties.put("ws-security.saml-callback-handler", samlCallbackHandler);
        
        properties.put("ws-security.signature.properties", "alice.properties");
        properties.put("ws-security.signature.username", "alice");
        properties.put("ws-security.encryption.properties", "bob-pub.properties");
        properties.put("ws-security.encryption.username", "bob");
        
//        properties.put("ws-security.self-sign-saml-assertion", "true");
        factory.setProperties(properties);
        //factory.getOutInterceptors().add(new SamlTokenInterceptor());
        HelloWorld client = factory.create(HelloWorld.class);
        System.out.println(client.sayHi("World"));
    }

}

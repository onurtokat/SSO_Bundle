package com.motive.ecs.applications.ssc.auth.turkcell;

import java.util.HashMap;

/**
 * A simulated response from an SSO request, simulating what kind of information you would require
 * when performing a "/validate" against an SSO integration.
 *
 * @author Zach Calvert
 */
public class SsoServerResponse {

    /**
     * Copyright 2014
     */
    public static final String COPYRIGHT = "Copyright (c) Motive 2014.  All rights reserved.";

    /**
     * Whether or not the token is valid (ie not expired, not null, can be parsed, is sufficient)
     */
    private boolean isValid;

    /**
     * The subscriber ID
     */
    private String subscriber;

    private HashMap<String, String> loginAttributes;

    /**
     * @return the isValid
     */
    public boolean isValid() {
        return isValid;
    }

    /**
     * @param isValid the isValid to set
     */
    public void setValid(boolean isValid) {
        this.isValid = isValid;
    }

    /**
     * @return the subscriber
     */
    public String getSubscriber() {
        return subscriber;
    }

    /**
     * @param subscriber the subscriber to set
     */
    public void setSubscriber(String subscriber) {
        this.subscriber = subscriber;
    }

    /**
     * @return the loginAttributes
     */
    public HashMap<String, String> getLoginAttributes() {
        return loginAttributes;
    }

    /**
     * @param loginAttributes the loginAttributes to set
     */
    public void setLoginAttributes(HashMap<String, String> loginAttributes) {
        this.loginAttributes = loginAttributes;
    }
}

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package models.secure;

import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Julien Durillon
 */
public class AuthUserImpl implements AuthUser {

    private Class authProvider;

    private String username;

    private Map<String,String> informations = new HashMap<String, String>();


    public AuthUserImpl(Class authprov, String username) {
        this.authProvider = authprov;
        this.username = username;
    }


    public void addField(String key, String value) {
        this.informations.put(key, value);
    }

    public Class authProvider() {
        return authProvider;
    }

    public String username() {
        return username;
    }

    public Map<String, String> informations() {
        return informations;
    }

}

package models.secure;

import java.util.Map;

/**
 *
 * @author Julien Durillon
 */
public interface AuthUser {

    public Class authProvider();

    public String username();

    public Map<String,String> informations();
}

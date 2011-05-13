package extension.secure;

import annotations.For;
import controllers.secure.Secure;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import models.secure.AuthUser;
import models.secure.AuthUserImpl;
import play.Play;
import play.classloading.ApplicationClasses.ApplicationClass;
import play.mvc.Controller;
import play.mvc.Scope.Session;
import play.mvc.results.Forbidden;
import play.utils.Java;

/**
 *
 * @author Julien Durillon
 */
public class SecurityExtensionPoint {


    public static boolean check(String profile) {
        return true;
    }

    public static void onCheckFailed() {
    }

    public static void onAuthenticated() {
    }

    public static List<Class<? extends SecurityExtensionPoint>> findFor(Class providerClass) {
        List<Class<? extends SecurityExtensionPoint>> classes = new LinkedList<Class<? extends SecurityExtensionPoint>>();
        List<Class<? extends SecurityExtensionPoint>> otherClasses = new LinkedList<Class<? extends SecurityExtensionPoint>>();

        for (ApplicationClass cl : Play.classes.getAssignableClasses(SecurityExtensionPoint.class)) {
            if (cl.javaClass.isAnnotationPresent(For.class)) {
                For annot = cl.javaClass.getAnnotation(For.class);
                Class<? extends SecurityManager> provFor = annot.value();
                if (provFor != null && provFor.equals(providerClass)) {
                    classes.add((Class<? extends SecurityExtensionPoint>) cl.javaClass);
                }
            } else {
                otherClasses.add((Class<? extends SecurityExtensionPoint>) cl.javaClass);
            }
        }
        if (classes.isEmpty()) {
            classes = otherClasses;
        }

        return classes;
    }


    public static List<Object> invokeFor(Class<? extends Secure> provider, String method, Object ... args) {
        List<Class<? extends SecurityExtensionPoint>> eps = findFor(provider);

        List<Object> retour = new ArrayList<Object>(eps.size());


        for(Class cl : eps) {
            try {
                retour.add(Java.invokeStaticOrParent(cl, method, args));
            } catch (Exception ex) {
                Logger.getLogger(SecurityExtensionPoint.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        return retour;
    }

    

}

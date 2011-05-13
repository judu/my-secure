package controllers.secure;

import annotations.Check;
import annotations.Provides;
import com.google.gson.Gson;
import controllers.secure.providers.BasicSecurityProvider;
import extension.secure.SecurityExtensionPoint;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import models.secure.AuthUser;
import play.Logger;
import play.Play;
import play.classloading.ApplicationClasses.ApplicationClass;
import play.modules.secure.SecureConf;
import play.modules.secure.SecureConf.ProviderParams;
import play.mvc.Before;
import play.mvc.Controller;
import play.mvc.Router;
import play.mvc.Router.Route;
import play.utils.Java;

/**
 *
 * @author Julien Durillon
 */
public class Secure extends Controller {

   public static String PROVIDER_KEY = "authprovider";

   @Before(priority = 100)
   static void checkAccess() {

      play.Logger.info("Action : %s", request.action);
      play.Logger.info("checkAccess Main controller class %s", getControllerClass().getCanonicalName());
      if (!Secure.class.isAssignableFrom(getControllerClass())) {
         if (!session.contains("username")) {
            flash.put("url", request.method.equals("POST") ? "/":request.url);
            flash.put("originalUrl", request.url);
            flash.put("originalVerb", request.method);
            displayChoice();
         }
         doCheck();
      }
   }

   protected static void doCheck() {

      play.Logger.debug("doCheck");
      Class providerClass;
      if (session.contains(PROVIDER_KEY)) {
         String providerName = session.get(PROVIDER_KEY);
         providerClass = getProvider(providerName);
      } else {
         providerClass = BasicSecurityProvider.class;
      }

      play.Logger.debug("Provider Class : %s", providerClass.getCanonicalName());
      List<Class<? extends SecurityExtensionPoint>> eps = SecurityExtensionPoint.findFor(providerClass);
      Check check = getActionAnnotation(Check.class);
      if (check != null) {
         checkWith(eps, check);
      }

      check = getControllerInheritedAnnotation(Check.class);
      if (check != null) {
         checkWith(eps, check);
      }

      play.Logger.debug("Check passed");
   }

   protected static void redirectToOriginalURL() {
      String url = flash.get("url");
      if (url == null) {
         url = "/";
      }
      redirect(url);
   }

   private static void checkWith(List<Class<? extends SecurityExtensionPoint>> eps, Check check) {
      play.Logger.debug("CheckWith");
      Boolean ok = true;
      for (Class<? extends SecurityExtensionPoint> cl : eps) {
         try {
            Boolean ok2 = false;
            for (String profile : check.value()) {
               ok2 = ok2 || (Boolean) Java.invokeStaticOrParent(cl, "check", profile);
            }
            ok = ok && ok2;
            if (!ok) {
               play.Logger.debug("Not ok");
               //TODO: invoke onCheckFailed
               SecurityExtensionPoint.invokeFor(getProvider(session.get(PROVIDER_KEY)), "onCheckFailed");
               forbidden();
            }
         } catch (Exception ex) {
            Logger.error(ex, "");
         }
      }
   }

   public static void doLogout() {
      Class cl = getProvider(session.get(PROVIDER_KEY));
      try {
         Java.invokeStaticOrParent(cl, "logout");
      } catch (Exception ex) {
         Logger.error(ex, "");
      }
   }

   public static void logout() {
      session.remove("username");
      session.clear();
      redirect("/");
   }

   public static AuthUser getAuthUser() {
      try {
         play.Logger.info(session.get(PROVIDER_KEY));
         return (AuthUser) Java.invokeStaticOrParent(getProvider(session.get(PROVIDER_KEY)), "doGetAuthUser");
      } catch (Exception ex) {
         Logger.error(ex, "");
         return null;
      }
   }

   public static Class<? extends Secure> getProvider(String provider) {
      if (provider != null) {

         for (ApplicationClass ac : Play.classes.getAssignableClasses(Secure.class)) {
            if (ac.javaClass.isAnnotationPresent(Provides.class)) {
               String value = ac.javaClass.getAnnotation(Provides.class).value();

               if (value != null && value.equals(provider)) {
                  return (Class<? extends Secure>) ac.javaClass; // We return the first found because there should only be one.
               }
            }
         }
      }
      return BasicSecurityProvider.class;
   }

   public static void displayChoice() {

      String originalUrl = flash.get("originalUrl");
      String originalVerb = flash.get("originalVerb");
      Map<String, String> route = Router.route(originalVerb, originalUrl.substring(0, originalUrl.indexOf("?")));

      if (route.containsKey("action")) {
         String action = route.get("action");

         List<ProviderParams> handlers = SecureConf.getHandlers(action);
         if (handlers != null) {
            Map<String, String> toDisplay = new HashMap<String, String>();

            for (ProviderParams pp : handlers) {
               try {
                  Class provider = getProvider(pp.name());
                  String url = Router.getFullUrl(provider.getName() + ".login");
                  String display = (String) Java.invokeStatic(provider, "getDisplayMessage", pp);
                  toDisplay.put(url, display);
               } catch (Exception ex) {
                  Logger.error("provider " + pp.name() + " does not have getDisplayMessage method");
               }
            }
            
            flash.keep();
            render(toDisplay);
         } else {
            BasicSecurityProvider.login();
         }
      }
   }
}
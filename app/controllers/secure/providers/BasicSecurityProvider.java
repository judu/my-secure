package controllers.secure.providers;

import annotations.Provides;
import java.util.logging.Level;
import java.util.logging.Logger;
import play.mvc.Before;
import controllers.secure.Secure;
import extension.secure.SecurityExtensionPoint;
import models.secure.AuthUser;
import models.secure.AuthUserImpl;
import play.data.validation.Required;
import play.data.validation.Validation;
import play.i18n.Messages;
import play.libs.Crypto;
import play.modules.secure.SecureConf.ProviderParams;
import play.mvc.Http;
import play.mvc.Router;
import play.utils.Java;

/**
 *
 * @author Julien Durillon
 */
@Provides("basic")
public class BasicSecurityProvider extends Secure {

   @Before(priority = 50, unless = {"login", "authenticate", "logout"})
   static void checkAccess() {
      play.Logger.debug("checkAccess Basic for %s", getControllerClass().getCanonicalName());

      flash.put(PROVIDER_KEY, "basic");

      if (!BasicSecurityProvider.class.isAssignableFrom(getControllerClass())) {
         play.Logger.debug("Not assignable from");
         if (!session.contains("username")) {
            play.Logger.debug("No username");
            flash.put("url", "POST".equals(request.method) ? "/" : request.url);
            login();
         }
         doCheck();
      }
   }

   public static void login() {
      flash.put(PROVIDER_KEY, "basic");

      Http.Cookie remember = request.cookies.get("rememberme");
      if (remember != null && remember.value.indexOf("-") > 0) {
         String sign = remember.value.substring(0, remember.value.indexOf("-"));
         String username = remember.value.substring(remember.value.indexOf("-") + 1);
         if (Crypto.sign(username).equals(sign)) {
            session.put("username", username);
            redirectToOriginalURL();
         }
      }
      flash.keep("url");
      flash.keep(PROVIDER_KEY);
      render();
   }

   public static void authenticate(@Required String username, String password, boolean remember) {
      // Check tokens
      Boolean allowed = false;

      for (Class cl : SecurityExtensionPoint.findFor(BasicSecurityProvider.class)) {
         try {
            play.Logger.info("Try with %s", cl.getCanonicalName());
            allowed = allowed || (Boolean) Java.invokeStaticOrParent(cl, "authenticate", username, password);
         } catch (Exception ex) {
            Logger.getLogger(BasicSecurityProvider.class.getName()).log(Level.SEVERE, null, ex);
         }
      }


      if (Validation.hasErrors() || !allowed) {
         flash.keep("url");
         flash.keep(PROVIDER_KEY);
         flash.error("secure.error");
         params.flash();
         login();
      }
      // Mark user as connected
      session.put("username", username);
      session.put(PROVIDER_KEY, "basic"); // Utile pour le logout

      // Remember if needed
      if (remember) {
         response.setCookie("rememberme", Crypto.sign(username) + "-" + username, "30d");
      }

      SecurityExtensionPoint.invokeFor(BasicSecurityProvider.class, "onAuthenticated");

      // Redirect to the original URL (or /)
      redirectToOriginalURL();
   }

   public static void logout() {
      session.clear();
      response.removeCookie("rememberme");
      redirect("/");
   }

   /**
    *
    * @param session Should be the current session
    * @return
    */
   public static AuthUser doGetAuthUser() {
      Class cl = getProvider(session.get(Secure.PROVIDER_KEY));
      if (session.get("username") != null) {
         AuthUser au = new AuthUserImpl(cl, session.get("username"));
         return au;
      } else {
         return null;
      }
   }

   public static String getLoginUrl(ProviderParams pp) {
      return Router.getFullUrl("secure.providers.BasicSecurityProvider.login");
   }

   public static String getDisplayMessage(ProviderParams pp) {
      return Messages.get("basic.display");
   }
}

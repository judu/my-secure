package play.modules.secure;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import play.Logger;
import play.Play;
import play.PlayPlugin;
import play.vfs.VirtualFile;

/**
 *
 * @author judu
 */
public class SecureConf extends PlayPlugin {

   private static Map<String, String> handling;
   private static Map<String, List<ProviderParams>> providers;
   public static final String SECURITY_CONF_FILE = "conf/security.conf";

   @Override
   public void onApplicationStart() {
      if (handling == null) {
         handling = new HashMap<String, String>();
      }
      if (providers == null) {
         providers = new HashMap<String, List<ProviderParams>>();
      }
      VirtualFile vf = Play.getVirtualFile(SECURITY_CONF_FILE);
      parseFile(vf);
   }

   private void parseFile(VirtualFile vf) {
      try {
         if (vf != null) {
            BufferedReader br = new BufferedReader(new InputStreamReader(vf.inputstream()));
            String line = null;
            int lineNumber = 0;
            while ((line = br.readLine()) != null) {
               ++lineNumber;
               Logger.debug("parsing line %s", line);
               parseLine(line, lineNumber);
            }
         }
      } catch (ParsingException ex) {
         Logger.error(ex, ex.getMessage());
      } catch (IOException ex) {
         Logger.error(ex, ex.getMessage());
      }
   }

   public static List<ProviderParams> getHandlers(String actionChain) {
      String handler = handling.get(actionChain);
      if (handler == null) {
         if (actionChain.contains(".")) {
            handler = handling.get(actionChain.substring(0, actionChain.indexOf(".")));
         }
      }
      if (handler != null) {
         return providers.get(handler);
      } else {
         return null;
      }
   }

   /**
    * Parse a line of the security.conf file.
    * 
    * A line's format is: 
    *    controller[.action]     provider
    * 
    * Where provider is the same as the value of the {@link annotations.Provides} 
    * annotation of the provider's class.
    * 
    * A special format is:
    *    import:module
    * 
    * Where module is the name of the module from which you want to import the
    * security.conf file.
    * 
    * @param line the String to parse.
    * @param lineNumber the number of the line (for logging purpose).
    * @throws ParsingException If it can't parse the line.
    */
   private void parseLine(String line, int lineNumber) throws ParsingException {
      try {
         String toTreat = line.trim();
         if (!line.isEmpty()) {
            if (line.startsWith("@")) {
               parseIdentifierDeclaration(toTreat);
            } else if (line.startsWith("import:")) {
               parseImport(toTreat);
            } else {
               parseNormalLine(toTreat);
            }
         }
      } catch (ParsingException ex) {
         throw new ParsingException("Parsing error in line " + lineNumber, ex);
      }
   }

   /**
    * Identifier declaration is like:
    * @iden    (((@otherid)|(prov1{name1:value1,name2:value2}))(,[ ]*))*
    * 
    * @param toTreat 
    */
   private void parseIdentifierDeclaration(String toTreat) throws ParsingException {
      String[] splitted = toTreat.split("\\s", 2);
      if(splitted.length != 2) {
         throw new ParsingException("La ligne de définition d'un @iden doit être de la forme : @iden   conf(param:arg),@otherid");
      }
      providers.put(splitted[0].trim(), parseProviderDefinitionList(splitted[1].trim()));
   }

   private List<ProviderParams> parseProviderDefinitionList(String provDefs) throws ParsingException {
      List<ProviderParams> pps = new LinkedList<ProviderParams>();
      while (!provDefs.isEmpty()) {
         if(provDefs.startsWith(",")) {
          provDefs = provDefs.substring(1);  
         }
         String bout = getPartOfConf(provDefs);
         
         int len = bout.length();
//         Logger.debug("bout : %s «%s»", len, bout);
//         Logger.debug("provdefs : %s «%s»", provDefs.length(), provDefs);
         provDefs = provDefs.substring(len);
         pps.addAll(parsePartOfConf(bout));
      }
      Logger.debug("providers : %s", pps);
      return pps;
   }

   private void parseImport(String toTreat) {
      VirtualFile vf = Play.modules.get(toTreat.substring(7)).child(SECURITY_CONF_FILE);
      parseFile(vf);
   }

   private void parseNormalLine(String toTreat) throws ParsingException {
      String[] splitted = toTreat.split("\\s", 2); // split the actionChain and the providers definitions

      if(splitted.length != 2) {
         throw new ParsingException("The format should be controller[.action]    listOf@idsOrProviders");
      }
      
      String actionChain = splitted[0].trim();
      String provs = splitted[1].trim();
      Logger.debug("actionchain : %s", actionChain);

      if (!provs.contains(",")
              && provs.startsWith("@")) {
         // Just use this @id
         handling.put(actionChain, provs);
      } else {
         // need to parse it and create temp id
         providers.put(actionChain, parseProviderDefinitionList(provs));
         handling.put(actionChain, actionChain);
      }
      
      Logger.debug("Line parsed : %s -> %s", actionChain, providers.get(handling.get(actionChain)));
   }

   private String getPartOfConf(String provDefs) {
      int vindex = provDefs.indexOf(",");
      if (provDefs.startsWith("@")) {
         return provDefs.substring(0, vindex > 0 ? vindex : provDefs.length()).trim();
      } else {
         if (vindex > 0) { // Si on a une virgule
            int pindex = provDefs.indexOf("(");
            if (pindex >= 0 && pindex < vindex) { // Si on a une parenthèse avant la virgule
               //On prend le nom + les parenthèses
               return provDefs.substring(0, provDefs.indexOf(")") + 1);
            } else {
               //On ne prend que le nom
               return provDefs.substring(0, vindex);
            }
         } else {
            return provDefs; // Si pas de virgule, on renvoie tout
         }
      }
   }

   private Collection<ProviderParams> parsePartOfConf(String bout) throws ParsingException {
      if (bout.startsWith("@")) {
         return providers.get(bout);
      } else {
         //Parse the def
         String[] parts = bout.split("\\(", 2);
         ProviderParams pp = new ProviderParams();
         pp.name = parts[0];
         if (parts.length > 1 && !parts[1].trim().isEmpty()) {

            String toParse = parts[1].trim();
            //parse params
            StringBuilder sb = new StringBuilder();
            String currentParam = null;
            Boolean isInQuotes = Boolean.FALSE, escaped = Boolean.FALSE, end = Boolean.FALSE;
            int i = -1;
            parse:
            while (++i < toParse.length()) {

               Character current = Character.valueOf(toParse.charAt(i));
               if (current.equals('\\')) {
                  if (++i == toParse.length()) {
                     break parse;
                  } else {
                     current = Character.valueOf(toParse.charAt(i));
                     escaped = Boolean.TRUE;
                  }
               }

               switch (current) {
                  case '"':
                     if (escaped) {
                        sb.append(current);
                     } else {
                        isInQuotes = !isInQuotes;
                     }
                     break;
                  case ',':
                     if (!isInQuotes) {
                        pp.conf.put(currentParam, sb.toString().trim());
                        sb = new StringBuilder();
                        currentParam = null;
                     } else {
                        sb.append(current);
                     }
                     break;
                  case ':':
                     if (!isInQuotes) {
                        currentParam = sb.toString().trim();
                        sb = new StringBuilder();
                     } else {
                        sb.append(current);
                     }
                     break;
                  case ')':
                     if (escaped || isInQuotes) {
                        sb.append(current);
                     } else {
                        end = Boolean.TRUE;
                        break parse;
                     }
                     break;
                  default:
                     sb.append(current);
               }
               escaped = Boolean.FALSE;
            }

            if (isInQuotes) {
               throw new ParsingException("You opened quotes you didn't close");
            } else if (currentParam != null) {
               // If currentParam != null, then we maybe just parsed the last value.
               // So, we need to save it.
               pp.conf.put(currentParam, sb.toString().trim());
            } else {
               // if null, we are after a ',' so there is an error…
               throw new ParsingException("The provider definition should end with a ')' if it has arguments.");
            }
         }

         List<ProviderParams> ps = new ArrayList<ProviderParams>(1);
         ps.add(pp);

         return ps;
      }
   }

   public static class ProviderParams {

      private String name;
      private Map<String, String> conf;

      public ProviderParams() {
         conf = new HashMap<String, String>();
      }

      public String name() {
         return this.name;
      }

      public String get(String key) {
         return this.conf.get(key);
      }

      @Override
      public String toString() {
         return "ProviderParams{" + "name=" + name + ", conf=" + conf + '}';
      }
   }
}

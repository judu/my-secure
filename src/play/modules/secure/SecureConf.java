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
      if(handler != null) {
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
      String toTreat = line.trim();
      if (line.startsWith("@")) {
         parseIdentifierDeclaration(toTreat);
      } else if (line.startsWith("import:")) {
         parseImport(toTreat);
      } else {
         parseNormalLine(toTreat);
      }
   }

   /**
    * Identifier declaration is like:
    * @iden    (((@otherid)|(prov1{name1:value1,name2:value2}))(,[ ]*))*
    * 
    * @param toTreat 
    */
   private void parseIdentifierDeclaration(String toTreat) throws ParsingException {
      int spaceindex = toTreat.indexOf(" ");
      String id = toTreat.substring(0, spaceindex);
      String provDefs = toTreat.substring(spaceindex + 1).trim();
      providers.put(id, parseProviderDefinitionList(provDefs));
   }

   private List<ProviderParams> parseProviderDefinitionList(String provDefs) throws ParsingException {
      List<ProviderParams> pps = new LinkedList<ProviderParams>();
      while (provDefs.length() > 0) {
         String bout = getPartOfConf(provDefs);
         provDefs = provDefs.substring(bout.length() + 1);
         pps.addAll(parsePartOfConf(bout));
      }
      return pps;
   }

   private void parseImport(String toTreat) {
      VirtualFile vf = Play.modules.get(toTreat.substring(7)).child(SECURITY_CONF_FILE);
      parseFile(vf);
   }

   private void parseNormalLine(String toTreat) throws ParsingException {
      int spaceindex = toTreat.indexOf(" ");
      String actionChain = toTreat.substring(0, spaceindex);
      String provs = toTreat.substring(spaceindex + 1).trim();

      if (!provs.contains(",")
              && provs.startsWith("@")) {
         // Just use this @id
         handling.put(actionChain, provs);
      } else {
         // need to parse it and create temp id
         providers.put(actionChain, parseProviderDefinitionList(provs));
         handling.put(actionChain, actionChain);
      }
   }

   private String getPartOfConf(String provDefs) {
      int vindex = provDefs.indexOf(",");
      if (provDefs.startsWith("@")) {
         return provDefs.substring(0, vindex > 0 ? vindex : provDefs.length()).trim();
      } else {
         int pindex = provDefs.indexOf("(");
         if (pindex >= 0 && pindex < provDefs.indexOf(",")) {
            //On prend le nom + les parenthèses
            return provDefs.substring(0, provDefs.indexOf(")") + 1);
         } else {
            //On ne prend que le nom
            return provDefs.substring(0, vindex);
         }
      }
   }

   private Collection<ProviderParams> parsePartOfConf(String bout) throws ParsingException {
      List<ProviderParams> list = new LinkedList<ProviderParams>();
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
   }
}

package play.modules.secure;

/**
 *
 * @author judu
 */
class ParsingException extends Exception {

   public ParsingException(String string) {
      super(string);
   }

   public ParsingException(String string, Exception ex) {
      super(string, ex);
   }
   
}

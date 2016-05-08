package jose;

import net.minidev.json.JSONArray;
import com.nimbusds.jwt.JWTClaimsSet;

public class JOSEUtil {

    public static void main(String[] args) {

        JWTClaimsSet jwtClaims = new JWTClaimsSet();
        
        JSONArray jsonArray = new JSONArray();
        
        jsonArray.add("maven-book");
        
        jwtClaims.setIssuer("https://packt.com");

        jwtClaims.setSubject("john");

        jwtClaims.setCustomClaim("book", jsonArray);        

    }

}

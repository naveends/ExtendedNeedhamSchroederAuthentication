import java.io.*;

/**
 * This is a DES class, encrypts or decrypts.
 * @author Naveen DS
 */
public class DesTriple {

	public String key_64;

	/**
	 * This is the constructor for this class which should be init by key
	 */
	public DesTriple (String key) {
		this.key_64 = key;
	}
	
	/*
	 * This is a method to init the objects with their keys
	 */
	public void init(String key) {
		this.key_64 = key;
	}

	/**
	 * This is a method to do encryption or decryption based on the bit
	 * @param eORd - Specify e for encryption, d for decryption
	 * @param message - message to encrypt
	 * @param type: des-ede for ECB and des-ede-cbc for cbc
	 * @return returns the encrypted string
	 */
	public String encORdec(String eORd, String message, String type) throws IOException {

		String[] edResult = stringizer(message, eORd, this.key_64, type);
		//System.out.println(java.util.Arrays.toString(edResult));
		String s = null;
		try {
			Process p = Runtime.getRuntime().exec(edResult);
			BufferedReader stdInput = new BufferedReader(new 
					InputStreamReader(p.getInputStream()));

			stdInput = new BufferedReader(new 
					InputStreamReader(p.getInputStream()));
			BufferedReader stdError = new BufferedReader(new 
	                 InputStreamReader(p.getErrorStream()));
			String output="";
			int flag = 0;
			while((s = stdInput.readLine()) != null)
			{
				//System.out.println("I m here");
				if (flag ==0)
				{
					output+=s;
					flag++;
				}
				else {
					output = output + "\n" + s;
				}
			}
			//System.out.println(output);
			 // read any errors from the attempted command
            //System.out.println("Here is the standard error of the command (if any):\n");
            while ((s = stdError.readLine()) != null) {
                System.out.println(s);
                return "error";
            }
            
			return output;
		}
		catch (Exception e) {
			System.out.println("exception happened - here's what I know: ");
			s = e.toString();
			return s;
			//System.exit(-1);
		}

	}

	/**
	 * Main method to test the DesTriple Class
	 */
	public static void main(String[] args) throws IOException {

		String key = "fbdb77a815b3d89a520d76e9416c9032"; 
		DesTriple alice = new DesTriple(key);
		String message = "U2FnaveensdGVkX1+PnlHP0zGwyfagS9uu9fzqCrIYC03QlXfMIls3ctAKwf2u7Vg+kjhklhkhkljhlkjlkjlkjlkjlkjleB/eedDwsk3LWZEH/41OQ2CdnhlYFdjj20FIKY0d1O3qi6qAMHtYy2xojCAsqInrBi4zghN5Ax34UB4=";
		String encrypted = alice.encORdec("e", message, "des-ede-cbc");
		System.out.println(encrypted + " is the encrypted text");
		String output = alice.encORdec("d", encrypted, "des-ede-cbc");
		System.out.println(output + " is the plain text");

	}

	/**
	 * This is a helper method for method encORDec
	 * This method creates command line arguments for running openssl based on input
	 * @param eVal the message that has to be encrypted
	 * @param eORd e for encryption, d for decryption
	 * @param key key that needs to be used
	 * @param type whether it is ecb or cbc
	 * @return returns command line argument string that runs in shell
	 */
	private static String[] stringizer(String eVal, String eORd, String key, String type) {

		if((type.equalsIgnoreCase("des-ede")) == false) {
			String[] cmd = {
					"/bin/sh",
					"-c",
					"echo \"" + eVal + "\" | openssl enc -" + eORd + " -a -" + type +" -k " + key
			};	
			return cmd;
		} else {
			String[] cmd = {
					"/bin/sh",
					"-c",
					"echo \"" + eVal + "\" | openssl enc -" + eORd + " -a -" + type +" -k " + key + " -nosalt -nopad"
			};
			return cmd;
		}
		//System.out.println(java.util.Arrays.toString(openssl enc -d -des-ede -nosalt -nopad -a -k nan));
	}

}

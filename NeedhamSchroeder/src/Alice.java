import java.io.*;
import java.net.*;
import java.security.SecureRandom;
import DesTriple;

/**
 * This is process Alice. Constructs, send and receive messages to KDC and Bob. 
 * @author Naveen DS 
 */
public class Alice {
	//This is to store information that is required by Trudy to perform reflection attack. 
	static String mess3ToBob = "";

	public static void main(String[] args) throws IOException {

		//Variables for connection to KDC
		Socket socket_KDC = null;
		PrintWriter out_KDC = null;
		BufferedReader in_KDC = null;

		//variables for connection to Bob
		Socket socket_Bob = null;
		PrintWriter out_Bob = null;
		BufferedReader in_Bob = null;

		//Initializing the Secure random number generator.
		SecureRandom secureRandom = new SecureRandom(); 
		//Calling nextBytes method to generate Random Bytes
		byte[] bytes = new byte[8];
		secureRandom.nextBytes(bytes);

		/**
		 * Code to connect to KDC, get the output and input streams along with
		 * the socket
		 */

		try {
			socket_KDC = new Socket("", 4444);
			out_KDC = new PrintWriter(socket_KDC.getOutputStream(), true);
			in_KDC = new BufferedReader(new InputStreamReader(
					socket_KDC.getInputStream()));
		} catch (UnknownHostException e) {
			System.err.println("Don't know about host KDC at port 4444.");
			System.exit(1);
		} catch (IOException e) {
			System.err.println("Couldn't get I/O for "
					+ "the connection to: KDC, port 4444. Please run KDC before running me.");
			System.exit(1);
		}
		//System.out.println("Connected to KDC, port 4444");

		/**
		 * Below code is to connect to Bob with the specified port, get the socket
		 * input and output streams
		 */
		try {
			socket_Bob = new Socket("localhost", 5555);
			out_Bob = new PrintWriter(socket_Bob.getOutputStream(), true);
			in_Bob = new BufferedReader(new InputStreamReader(
					socket_Bob.getInputStream()));
		} catch (UnknownHostException e) {
			System.err.println("Don't know about host Bob at port 5555.");
			System.exit(1);
		} catch (IOException e) {
			System.err.println("Couldn't get I/O for "
					+ "the connection to: Bob, port 5555. Please run Bob before running me");
			System.exit(1);
		}
		//System.out.println("Connected to Bob, port 5555");

		//code to check the connection with KDC and Bob which echoes back for now
		//checkConnectionStatus(out_KDC, in_KDC);
		//checkConnectionStatus(out_Bob, in_Bob);

		//Extended Needham Schroeder Attack
		System.out.println("****************This is Extended Needham Schroeder Protocol ****************");
		//Below code is for sending first message to bob and getting the nonce from his reply
		String encNonce = sendExtraMessForExtended(in_Bob, out_Bob);
		performNeedhamSchroeder(socket_KDC, in_KDC, out_KDC, socket_Bob, in_Bob, out_Bob, secureRandom, 0, encNonce,0);
		System.out.println("****************End of Extended Needham Schroeder***************************\n");

		//Code for attack case
		System.out.println("****************This is Needham Schroeder Protocol with reflection attack done ****************");
		//connection to Bob again.
		try {
			socket_Bob = new Socket("localhost", 5555);
			out_Bob = new PrintWriter(socket_Bob.getOutputStream(), true);
			in_Bob = new BufferedReader(new InputStreamReader(
					socket_Bob.getInputStream()));
		} catch (UnknownHostException e) {
			System.err.println("Don't know about host Bob at port 5555.");
			System.exit(1);
		} catch (IOException e) {
			System.err.println("Couldn't get I/O for "
					+ "the connection to: Bob, port 5555.");
			System.exit(1);
		}
		//System.out.println("Connected to Bob, port 5555");
		performNeedhamSchroeder(socket_KDC, in_KDC, out_KDC, socket_Bob, in_Bob, out_Bob, secureRandom, 1, "",0);
		System.out.println("****************End of Needham Schroeder with Reflection attack***************************\n");
		//Code to show that with CBC, reflection attack will not work
		System.out.println("****************This is Needham Schroeder Protocol with attack done on CBC****************");
		//connection to bob again
		try {
			socket_Bob = new Socket("localhost", 5555);
			out_Bob = new PrintWriter(socket_Bob.getOutputStream(), true);
			in_Bob = new BufferedReader(new InputStreamReader(
					socket_Bob.getInputStream()));
		} catch (UnknownHostException e) {
			System.err.println("Don't know about host Bob at port 5555.");
			System.exit(1);
		} catch (IOException e) {
			System.err.println("Couldn't get I/O for "
					+ "the connection to: Bob, port 5555.");
			System.exit(1);
		}
		//System.out.println("Connected to Bob, port 5555");
		//System.out.println("This is going to be non attack case");
		performNeedhamSchroeder(socket_KDC, in_KDC, out_KDC, socket_Bob, in_Bob, out_Bob, secureRandom, 0, "", 1);
		System.out.println("****************End of Needham Schroeder with attack which failed***************************\n");

		//code to close the connections

		out_Bob.close();
		in_Bob.close();
		socket_Bob.close();

		out_KDC.close();
		in_KDC.close();
		socket_KDC.close();

	}

	/**
	 * This method is supposed to send two extra messages on top, for Extended Needham schroeder protocol.
	 * @param in_Bob is the input stream of Bob
	 * @param out_Bob is the output stream of Bob
	 * @return Returns the encrypted nonce sent by Bob
	 */
	private static String sendExtraMessForExtended(BufferedReader in_Bob, PrintWriter out_Bob) throws IOException {

		String encNonceFromBob = sendAndGet("1,Alice", in_Bob, out_Bob);
		System.out.println("\"Message A\" of Extended protocol from Alice to Bob: " + "1, Alice");
		System.out.println("\"Message B\" of Extended protocol from Bob to Alice: " + encNonceFromBob);
		return encNonceFromBob;
	}

	/**
	 * This method is to perform NeedhamSchroder Protocol, original version.
	 * Method, sends messages 1, 3 and 5 and gets the messages 2 and 4. 
	 * Also based on the type of parameters, ECB or CBC will be used for encryptions.
	 * @param socket_KDC is the socket for KDC
	 * @param in_KDC is the input stream for KDC connection
	 * @param out_KDC is the outputstream for KDC connection
	 * @param socket_Bob is the socket for Bob
	 * @param in_Bob is the input stream for Bob's connection
	 * @param out_Bob is the output stream for Bob's connection
	 * @param secureRandom is the random number generator object created in main
	 * @param encNonce is the nonce that is used in extended version of the protocol
	 * @param attackOnCBC this is set when you need to attack under CBC
	 * @param attack is set when you need to use Triple DES with ECB, otherwise set to zero. So that the messages are vulnerable
	 * 		  and protocol is vulnerable to reflection attack.
	 * @return Returns nothing. 
	 */
	private static void performNeedhamSchroeder(Socket socket_KDC, BufferedReader in_KDC, 
			PrintWriter out_KDC, Socket socket_Bob, BufferedReader in_Bob, 
			PrintWriter out_Bob, SecureRandom secureRandom, int attack, String encNonce, int attackOnCBC) throws IOException {

		//variables required for DES
		//String key_alice_bob = "efbc231bb8909edcb74fdf9144bc3b0b";
		//DesTriple alice_bob = new DesTriple(key_alice_bob);
		//Using the DesTriple class to create objects.
		
		//Both the keys are together, openssl requires two keys to be given together as single keys
		String key_Alice = "fbdb77a815b3d89a520d76e9416c9032";
		DesTriple alice = new DesTriple(key_Alice);

		//Call this method to contact KDC for ticket to Bob  --- Message 1	
		long randomNonce = Math.abs(secureRandom.nextLong());
		String bobTicketFromKDC = getBobTicketFromKDC(randomNonce,"Bob",encNonce, socket_KDC, in_KDC, out_KDC);
		//decrypting the ticket obtained from Bob
		String decryptedMessageFromKDC = alice.encORdec("d", bobTicketFromKDC, "des-ede-cbc");
		System.out.println("The decrypted ticket message from KDC is "+ decryptedMessageFromKDC);
		String[] checkMessage = decryptedMessageFromKDC.split(",");
		if (checkMessage[0].equalsIgnoreCase(String.valueOf(randomNonce)) != true || checkMessage[1].equalsIgnoreCase("Bob") != true ){
			System.out.println("Something is not correct here !, somebody has eavesdropped and impersonated me :(");
		}
		//checkMEssage[3] is the key Kab sentby KDC to Alice
		String key_alice_bob = checkMessage[3];
		DesTriple alice_bob = new DesTriple(key_alice_bob);
		System.out.println("The key sent by KDC is " + key_alice_bob);

		//Calling the method to contact Bob and send ticket, Kab(another nonce)  -----Message 3
		String randomNonceStr = String.valueOf(Math.abs(secureRandom.nextLong()));
		//System.out.println("nonceSelected for N2 is " + randomNonce);
		String randomNonceEnc, tmpRandomNonceStr;
		tmpRandomNonceStr = randomNonceStr;
		String type = "des-ede-cbc";
		if (attack == 1) {
			randomNonceStr = stringizerForAttack(randomNonce, 15);
			tmpRandomNonceStr = randomNonceStr;
			randomNonceStr = stringizer_big(randomNonceStr,32);
			System.out.println(randomNonceStr);
			type = "des-ede";
		} 
		// TODO: In this place stringizer should not be there and out in, have put in lets see
		randomNonceEnc = alice_bob.encORdec("e", randomNonceStr, type);
		if (attack == 1)
		{
			// Doing CBC encryption also and showing the difference.
			System.out.println("The encrypted \"message3\" with 3-DES ECB is " + randomNonceEnc);
			System.out.println("The encrypted \"message3\" with 3-DES CBC is " +alice_bob.encORdec("e", randomNonceStr, "des-ede-cbc"));
		}
		String messageFromBob = sendAndGetNonceBob(randomNonceEnc, checkMessage[2], socket_Bob, in_Bob, out_Bob, attack);

		//Code starts for sending message5
		String messageFromBobDec = alice_bob.encORdec("d", messageFromBob, type);
		if(attack == 1) {
			//Doing CBC encryption of message to display difference
			System.out.println("The encrypted \"message4\" with 3-DES ECB is " + messageFromBob);
			System.out.println("The encrypted \"message4\" with 3-DES CBC is " + alice_bob.encORdec("e", messageFromBobDec, "des-ede-cbc"));
		}
		//System.out.println("******Message 5******");
		System.out.println("\"Message5\", from Bob: " + messageFromBob);
		checkMessage= messageFromBobDec.split(",");
		if (attack == 1) {
			//here the message obtained has to be converted to long before checking.
			checkMessage[0] = checkMessage[0].replace(" ", "");
			checkMessage[1] = checkMessage[1].replace(" ", "");
			//System.out.println(checkMessage[1].length());
			tmpRandomNonceStr = (tmpRandomNonceStr).substring(0,15);
		}
		//System.out.println(Long.parseLong((randomNonceStr).substring(0,14)));
		//Checking whether bob has sent the correct response for the Nonce sent
		if ( Long.parseLong(checkMessage[0]) == (Long.parseLong(tmpRandomNonceStr))-1) {
			System.out.println("Bob is \"authenticated\" !! :)");
			//now need to send kab{N3-1}
			String lastMessage = String.valueOf(Long.parseLong(checkMessage[1])-1);
			if(attack == 0) {
				out_Bob.println("3" +  "," + alice_bob.encORdec("e", lastMessage, "des-ede-cbc"));
			} else {
				//This is to use ECB mode of triple DES and also padding the message
				//System.out.println(stringizer_big(lastMessage,16) + " 00 00 00 00 00 00 00 00");
				out_Bob.println("33" +  "," + alice_bob.encORdec("e", stringizer_big(lastMessage,16) + " 00 00 00 00 00 00 00 00", "des-ede"));
				System.out.println("The encrypted \"message5\" with 3-DES ECB is " + alice_bob.encORdec("e", stringizer_big(lastMessage,16) + " 00 00 00 00 00 00 00 00", "des-ede"));
				System.out.println("The encrypted \"message5\" with 3-DES CBC is " + alice_bob.encORdec("e", lastMessage, "des-ede-cbc"));
			}
			System.out.println(in_Bob.readLine());
		} else {
			System.out.println("Oops something is wrong :(, nonce reply does not match, checkMessage[0]" + checkMessage[0] + " " + (Long.parseLong((tmpRandomNonceStr).substring(0,15))));
		}
		//System.out.println("********End of Needham Schroeder*********\n");
		// End of Code for Ordinary Needham Schroeder
		/*
		 * Now starts the code for Reflection attack. This code will initiate Trudy
		 * and she will do the attack.
		 */
		if(attack == 1 || attackOnCBC == 1) {
			System.out.println("********Reflection attack will start*********\n");
			Trudy T = new Trudy();
			T.performReflectionAttack(mess3ToBob, messageFromBob);
		}
	}



	/**
	 * This is a method for Alice to contact KDc asking the ticket
	 * @param randomNonce is the nonce used
	 * @param who is the person you need to contact, usually it is Bob
	 * @param encryptedNonce is the nonce obtained from Bob in Extended Needham Schroeder protocol,
	 * 		  for normal, pass ""
	 */
	private static String getBobTicketFromKDC(long randomNonce, String who,
			String encryptedNonce, Socket socket_KDC, BufferedReader in_KDC, PrintWriter out_KDC) throws IOException {
		//constructing a string to be sent to KDC, and send it
		String message1 = randomNonce + "," + who + "," +encryptedNonce;
		System.out.println("\"Message1\", From Alice to KDC: " + message1);
		String message2 = sendAndGet(message1, in_KDC, out_KDC);
		System.out.println("\"Message2\", From KDC to Alice containing ticket to Bob");
		return message2;

	}

	/**
	 * 
	 * @param - attack is to set a different number to message than 2, so that Bob can understand.
	 * This is the message3 of the protocol (Plain Needham Schroeder).
	 */
	private static String sendAndGetNonceBob(String randomNonce,
			String ticket, Socket socket_Bob,
			BufferedReader in_Bob, PrintWriter out_Bob, int attack) throws IOException {
		String num = "2";
		if (attack == 1) num = "4";
		//Sending 2 to tell the type of message to bob, 4 will be sent so that ECB will be used by Bob as well
		String toBeSent = num + "," + ticket + "," + randomNonce;

		//This is to avoid the messaged being multiple lines
		toBeSent = toBeSent.replace("\n", ")");
		System.out.println("\"Message3\", sent from Alice to Bob with ticket: " + toBeSent);

		mess3ToBob = toBeSent;
		//System.out.println("This is the ticket with nonce sent to bob" + toBeSent);
		String message4 = sendAndGet(toBeSent, in_Bob, out_Bob);
		return message4;
	}

	/**
	 * This is a method to send and receive the packets. Generic method.
	 * @param message1 is the message to be sent
	 * @param in is the Inputstream for the socket to be used
	 * @param out is the output stream used
	 */
	private static String sendAndGet(String message1, BufferedReader in, PrintWriter out) throws IOException {

		//sending the message
		out.println(message1);
		String message2 = "";
		String s;
		int flag = 0;
		//receiving the message
		while(!(s = in.readLine()).equals("\u0004")) {
			if (flag==0) {
				message2 += s;
				flag++;
			} else {
				message2 = message2 + "\n" + s;
			}
		}
		//System.out.println(message2 + " is the message obtained from KDC");
		return message2;
	}

	/**
	 * This is a method to create messages vulnerable to attack
	 * Reason to do this: ECB is block cipher, so it needs a correct block size, so we are doing a padding here
	 * and this is created in this method
	 * @param num is the randomNumber
	 * @param lenReq is the length of the String required.
	 */
	private static String stringizerForAttack(long num, int lenReq) {

		String number = String.valueOf(num);
		String padding = "00000000000000000";
		return number.substring(0, lenReq) + padding;

	}

	/**
	 * This is a helper method that will add spaces in between two characters of the message to be sent
	 * This is required because, openssl when used with ECB requires the input in this format.
	 * @param num is the message
	 * @param lenReq is the required length your message needs to be
	 * @return returns a string of the requested constraint.
	 */
	private static String stringizer_big(String num, int lenReq) {

		String number = num;
		if(number.length() < lenReq)
		{
			//here the length of long generated is less than lenReq, we are padding and returning
			int count = lenReq - number.length();
			for (int i = 0; i < count; i++) {
				number += "0";
			}
			return number;
		}
		//System.out.println(number.length() + " " +number);
		int counter=0;
		String toBeReturned = "";
		for (counter = 0; counter < lenReq; counter = counter+2 ) {
			if (counter == 0) 
				toBeReturned += number.substring(counter, counter+2);
			else 				
				toBeReturned = toBeReturned + " " + number.substring(counter, counter+2);
		}
		return toBeReturned;
	}

	/**
	 * This is just a method to check the connection status
	 */
	/*private static void checkConnectionStatus(PrintWriter out, BufferedReader in) throws IOException {

		BufferedReader stdIn = new BufferedReader(
				new InputStreamReader(System.in));
		String userInput;

		userInput = stdIn.readLine();
		out.println(userInput);
		System.out.println("echo: " + in.readLine());

	}*/

}
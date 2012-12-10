import java.net.*;
import java.security.SecureRandom;
import java.io.*;

/**
 * This is class Bob, acts as Bob in NEedham Schroeder protocol.
 * Contains threads, so that it can support multiple connections
 * @author Naveen DS
 *
 */
public class Bob implements Runnable{

	static ServerSocket serverSocket = null;
	static Socket clientSocket = null;
	static DesTriple alice_bob;


	public static void main(String[] args) throws IOException {


		// Below lines makes the sever listen to the port specified
		try {
			serverSocket = new ServerSocket(5555);
		} catch (IOException e) {
			System.err.println("Could not listen on port: 5555, may be I am already running, please stop that and start me again");
			System.exit(1);
		}
		System.out.println("Listening to port 5555, I am Bob");

		//This is for accepting the client's connection
		while(true) {
			try {
				clientSocket = serverSocket.accept();
				//System.out.println("Accepted");
				(new Thread(new Bob())).start();
			} catch (IOException e) {
				System.err.println("Accept failed.");
				System.exit(1);
			}
		}

		//clientSocket.close();
		//serverSocket.close();
	}

	/**
	 * This is run method that runs when new thread is created.
	 * Takes care of sending and receiving messages for the protocol
	 */
	public void run(){

		//System.out.println("This is a new thread!");
		//Creating the input and output streams.
		PrintWriter out = null;
		BufferedReader in = null;
		try {
			out = new PrintWriter(clientSocket.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
		} catch (IOException e) {
			e.printStackTrace();
		}
		String inputLine;
		//Initializing the Secure Random number generator.
		SecureRandom secureRandom = new SecureRandom(); 
		//Calling nextBytes method to generate Random Bytes
		byte[] bytes = new byte[8];
		secureRandom.nextBytes(bytes);

		//DES keys and objects
		//Both the keys are together, openssl requires two keys to be given together as single keys
		String key_bob = "4db6e4bca143bb21f63cdae4af6c1784";
		DesTriple bob = new DesTriple(key_bob);
		//String key_alice_bob = "efbc231bb8909edcb74fdf9144bc3b0b";
		//DesTriple alice_bob = new DesTriple(key_alice_bob);

		long nonceN3 = 0;
		long nonceNb = 0;
		//This is a loop to get the input from socket !
		try {
			while ((inputLine = in.readLine()) != null) {
				String[] message = inputLine.split(",");
				if(message.length != 1)
					System.out.println("Message obtained from Alice is " + inputLine);
				//System.out.println(java.util.Arrays.toString(message));
				if (message[0].equalsIgnoreCase("1")) {
					//This is part of extended needham schroeder protocol, Bob needs to send the ticket here!
					System.out.println("In extended version of the protocol !");
					nonceNb = Math.abs(secureRandom.nextLong());
					String encNonce = bob.encORdec("e", String.valueOf(nonceNb), "des-ede-cbc");
					System.out.println("The nonce generated is " + nonceNb + " and encrypted version is " + encNonce);
					out.println(encNonce);

				} else if (message[0].equalsIgnoreCase("2")) {
					//This is part of both protocols. Message sent from Alice is {ticket,Kab(nonce)}
					//Need to subtract the number by 1 and send to Alice along with a new random nonce.

					message[1] = message[1].replace(")", "\n");
					//System.out.println(message[1] + " is the replaced text");
					//deletion sjould be done till here

					String ticket = bob.encORdec("d", message[1], "des-ede-cbc");
					String[] splitTicket = ticket.split(" ");
					//System.out.println(java.util.Arrays.toString(splitTicket));

					if (splitTicket[0].equalsIgnoreCase("99.0") != true) {
						System.out.println("You got it wrong Alice!, I am closing your connection");
						out.close();
					} else  {
						System.out.println("Ticket is perfect, getting the key now!");
						String key_alice_bob = splitTicket[1];
						System.out.println("The ticket for Kab is " + key_alice_bob);
						//creating des object
						alice_bob = new DesTriple(key_alice_bob);
						if(splitTicket.length == 3) {
							//This will occur in the extended version of the protocol, where nonce is sent with ticket
							String nonceCheck = bob.encORdec("d", splitTicket[2], "des-ede-cbc");
							if (Long.parseLong(nonceCheck) == nonceNb) {
								System.out.println("Nonce is perfect as is, I am speaking to Alice");
							} else System.out.println("Nonce I sent is not intact, some one is impersonating Alice");
						}
					}
					String nonceFromAlice = alice_bob.encORdec("d", message[2], "des-ede-cbc");
					if(nonceFromAlice.contains("error")) {
						System.out.println("Error while decrypting, either someone is impersonating Alice or Alice is sending wrongly");
						out.println("error");
						System.out.println("***************************************************");
					} else {
						long nonce = Long.parseLong(nonceFromAlice);
						//System.out.println(nonce + " is the nonce obtained from that side");
						nonce--;
						nonceN3 = Math.abs(secureRandom.nextLong());
						String toBeSentAlice = String.valueOf(nonce) + "," + String.valueOf(nonceN3);
						String toBeSentAliceEnc = alice_bob.encORdec("e", toBeSentAlice, "des-ede-cbc");
						System.out.println("\"Message4\" sent to Alice" + toBeSentAliceEnc);
						out.println(toBeSentAliceEnc);
					}

				} else if (message[0].equalsIgnoreCase("4")) {
					//This is when the algorithm used is ECB when sending message 4 so that, reflection attack is possible.
					//Otherwise the code is same as when message[0] is 2

					message[1] = message[1].replace(")", "\n");
					//System.out.println(message[1] + " is the replaced text");
					//deletion sjould be done till here

					String ticket = bob.encORdec("d", message[1], "des-ede-cbc");
					String[] splitTicket = ticket.split(" ");
					//System.out.println(java.util.Arrays.toString(splitTicket));
					if (splitTicket[0].equalsIgnoreCase("99.0") != true) {
						System.out.println("You got it wrong Alice!, I am closing your connection");
						out.close();
					} else  {
						System.out.println("Ticket is perfect, getting the key now!");
						String key_alice_bob = splitTicket[1];
						System.out.println("The ticket for Kab is " + key_alice_bob);
						//Creating objects for using DES
						alice_bob = new DesTriple(key_alice_bob);
					}

					String nonceFromAlice = alice_bob.encORdec("d", message[2], "des-ede");
					System.out.println("\"Message4, from Alice is \"" + nonceFromAlice);
					nonceFromAlice =nonceFromAlice.replace(" ", "");
					String nonceFromAliceStr = nonceFromAlice.substring(0, 15);
					long nonce = Long.parseLong(nonceFromAliceStr);
					//System.out.println(nonce + " is the nonce obtained from that side");
					nonce--;
					nonceN3 = Math.abs(secureRandom.nextLong());
					//System.out.println(nonceN3);
					String nonceN3Str = stringizerForAttack(nonceN3,16);
					String toBeSentAlice = stringizerForAttack(nonce,15) + ", " + nonceN3Str;
					nonceN3 = Long.parseLong(nonceN3Str.replace(" ", ""));
					String toBeSentAliceEnc = alice_bob.encORdec("e", toBeSentAlice, "des-ede");
					System.out.println("The encrypted \"message4\" that is sent to Alice is " + toBeSentAliceEnc);
					out.println(toBeSentAliceEnc);
					//System.out.println("*********************************************************");
				} else {
					//if message[0] is 3, if ok, authentication done.
					//if 33, we are in ECB, for reflection attack.
					if (message[0].equalsIgnoreCase("3") || message[0].equalsIgnoreCase("33")) {
						String type = "des-ede-cbc";
						if (message[0].equalsIgnoreCase("33")) type = "des-ede";
						System.out.println("Message 5 details");
						String nonceFromAlice2 = alice_bob.encORdec("d", message[1], type);
						//System.out.println(nonceFromAlice2 + " is the nonce for the last message from Alice");
						nonceFromAlice2 = nonceFromAlice2.replace(" ", "");
						System.out.println("The reply for nonce from Alice " + nonceFromAlice2);
						//getting the nonce from the message Alice sent
						long randTmp;
						if(nonceFromAlice2.subSequence(15, 16).equals(",")) 
							randTmp = Long.parseLong(nonceFromAlice2.substring(0, 15));
						else
							randTmp = Long.parseLong(nonceFromAlice2.substring(0, 16));
						//System.out.println(randTmp + "  " + nonceN3);
						if (randTmp == nonceN3-1){
							out.println("Thanks Alice for authing me, I have authed you as well :) - from Bob");
							System.out.println("Thanks Alice for authing me, I have authed you as well :) - from Bob");
							System.out.println("***************End of the protocol **************\n");
						} else {
							//This is a special case where the info will be contained in another during ECB
							String temp = String.valueOf(nonceN3).substring(0, String.valueOf(nonceN3).length()-1);
							long templ = Long.parseLong(temp);
							templ--;
							if(String.valueOf(templ).contains(String.valueOf(randTmp))) {
								System.out.println("Thanks Alice for authing me, I have authed you as well :) - from Bob");
								out.println("Thanks Alice for authing me, I have authed you as well :) - from Bob");
								System.out.println("****************************\n");
							} else 
								System.out.println("There is something wrong!!, are you impersonating Alice ?, nonces do not match, I am closing the connection, numbers are :" + randTmp + " " + nonceN3);
							System.out.println("*****************************\n");
						}
					}
				}
				//out.println(inputLine);
				out.println("\u0004");
			}
		} catch (NumberFormatException e) {
			//e.printStackTrace();
			System.out.println("");
		} catch (IOException e) {
			//e.printStackTrace();
			System.out.println("");
		}
		//closes the connections
		out.close();
		try {
			in.close();
		} catch (IOException e) {
			//e.printStackTrace();
			System.out.println("");
		}
	}

	/**
	 * This is a method to create messages vulnerable to attack
	 * Reason to do this: ECB is block cipher, so it needs a correct block size
	 * and this is created in this method
	 * @param num is the randomNumber
	 * @param lenReq is the length of the String required.
	 */
	private static String stringizerForAttack(long num, int lenReq) {

		String number = String.valueOf(num);
		if(number.length() < lenReq)
		{
			//here the length of long generated is less than lenReq, we are padding and returning
			int count = lenReq - number.length();
			for (int i = 0; i < count; i++) {
				number += "0";
			}
			return number;
		}
		System.out.println(number.length() + " " +number);
		int counter=0;
		String toBeReturned = "";
		for (counter = 0; counter < lenReq; counter = counter+2 ) {
			if (counter == 14 && lenReq == 15) {
				toBeReturned = toBeReturned + " " + number.substring(counter, 15);
				break;
			}
			if (counter == 15 && lenReq == 16) {
				toBeReturned = toBeReturned + " " + number.substring(counter, 17);
				break;
			}
			if (counter == 0) 
				toBeReturned += number.substring(counter, counter+2);
			else 				
				toBeReturned = toBeReturned + " " + number.substring(counter, counter+2);

		}
		return toBeReturned.substring(0, lenReq+7);

	}
}
import java.net.*;
import java.io.*;

/**
 * This is KDC. Which mediates authentication between users
 * Creates key for the users to contact each other and sends along with ticket.
 * @author Naveen DS
 *
 */
public class KDC {
	public static void main(String[] args) throws IOException {

		//Creating information required for DES, keys and objects
		//Both the keys are together, openssl requires two keys to be given together as single keys
		String key_Alice = "fbdb77a815b3d89a520d76e9416c9032";
		String key_Bob = "4db6e4bca143bb21f63cdae4af6c1784";
		
		DesTriple alice = new DesTriple(key_Alice);
		DesTriple bob = new DesTriple(key_Bob);
		
		//Creating objects and variables for communication		
		ServerSocket serverSocket = null;
		// Below lines makes the sever listen to the port specified
		try {
			serverSocket = new ServerSocket(4444);
		} catch (IOException e) {
			System.err.println("Could not listen on port: 4444.");
			System.exit(1);
		}
		System.out.println("Listening to port 4444, I am KDC");
		Socket clientSocket = null;
		//This is for accepting the client's connection
		try {
			clientSocket = serverSocket.accept();
		} catch (IOException e) {
			System.err.println("Accept failed.");
			System.exit(1);
		}

		//getting the input stream and output stream for communication
		PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
		BufferedReader in = new BufferedReader(
				new InputStreamReader(
						clientSocket.getInputStream()));
		String inputLine;
		while ((inputLine = in.readLine()) != null) {
			System.out.println("The message obtained is " + inputLine);
			String[] message = inputLine.split(",");
			if (message.length == 2) {
				/**
				 * here we have ordinary Needham Schroeder Protocol.
				 * Send (N1, Bob, ticket encrypted with Bob's key) encrypted with Alice's key
				 */
				//this is just for checking at the other side
				double ticket_bob = 99.0;
				String key_alice_bob = "efbc231bb8909edcb74fdf9144bc3b0b";
				//Sending the ticket with the key Kab so that bob can extract this.
				String ticket_to_bob= String.valueOf(ticket_bob)+ " " + key_alice_bob;
				String encrypted_ticket_Bob = bob.encORdec("e", ticket_to_bob, "des-ede-cbc");
				System.out.println("Encrypted ticket to Bob is "+ encrypted_ticket_Bob);
				String message2 = message[0] + "," + message [1] + "," + encrypted_ticket_Bob + "," + key_alice_bob ;
				//System.out.println(message2);
				String encrypted_message2 = alice.encORdec("e", message2, "des-ede-cbc");
				System.out.println("Message sent back is " + encrypted_message2);
				out.println(encrypted_message2);
				out.println("\u0004");
				
			} else if (message.length == 3) {
				//we perform work for Extended Needham Schroeder
				//extract Nb. Create Kab, send Kab(n1, bob, ticket)
				//ticket is kb (Kab, alice)
				//Send (N1, Bob, ticket encrypted with Bob's key) encrypted with Alice's key
				System.out.println("In the extended version of the protocol");
				double ticket_bob = 99.0;
				String key_alice_bob = "efbc231bb8909edcb74fdf9144bc3b0b";
				//Sending the ticket with the key Kab so that bob can extract this., ticket_to_bob contains ticket,kab,encrypted nonce bob sent to alice
				String ticket_to_bob= String.valueOf(ticket_bob)+ " " + key_alice_bob + " " + message[2];
				String encrypted_ticket_Bob = bob.encORdec("e", ticket_to_bob, "des-ede-cbc");
				System.out.println("Encrypted ticket to Bob is "+ encrypted_ticket_Bob);
				String message2 = message[0] + "," + message [1] + "," + encrypted_ticket_Bob + "," + key_alice_bob ;
				//System.out.println(message2);
				String encrypted_message2 = alice.encORdec("e", message2, "des-ede-cbc");
				System.out.println("Message sent back is " + encrypted_message2);
				out.println(encrypted_message2);
				out.println("\u0004");
			} else {
				//This is just for testing
				out.println(inputLine);
			}
			if (inputLine.equals("Bye."))
				break;
		}
		
		//closes the connections
		out.close();
		in.close();
		clientSocket.close();
		serverSocket.close();
	}
}
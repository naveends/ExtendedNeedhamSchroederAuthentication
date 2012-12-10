import java.io.*;
import java.net.*;


/**
 * This is class Trudy
 * She does reflection attack
 * @author Naveen DS
 *
 */
public class Trudy {

	public static void main (String args[]) {
		//Nothing here !!
	}

	/**
	 * Intended to replay message3 to Bob, get message4, split into 2
	 * Opens another connection, send that now (after splitting ticket from message3)
	 * Gets the output for nonce sent by Bob, attack with message4(already eavesdropped)
	 * and get itself authenticated.
	 * @param message3Enc is the message3 of ordinary Needham Schroder protocol
	 * @param message4Enc is the message4 (same as above)
	 */
	public void performReflectionAttack(String message3Enc, String message4Enc) throws IOException {


		//create connections to Bob, sockets, streams
		//variables for connection to Bob
		Socket socket_Bob = null;
		PrintWriter out_Bob = null;
		BufferedReader in_Bob = null;

		//for second connection
		Socket socket_Bob_2 = null;
		PrintWriter out_Bob_2 = null;
		BufferedReader in_Bob_2 = null;

		/*
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
					+ "the connection to: Bob, port 5555.");
			System.exit(1);
		}
		//System.out.println("Connected to Bob, port 5555");

		//Code for the attack will begin here
		//First replay the message3 to Bob and get his reply.
		//we get new nonce n4
		System.out.println("Starting reflection attack, replaying message3 now!");
		String replyFromBob = sendAndGet(message3Enc, in_Bob, out_Bob);
		System.out.println("Reply from Bob is " + replyFromBob);
		int len = replyFromBob.length();
		//Holding this connection, she is doing reflection attack now
		//Put the second half of this reply into message3Enc instead of Kab{N2}
		//thereby asking the value of nonce n4-1

		String[] message3Split = message3Enc.split(",");
		String attackMessage = message3Split[0] + "," + message3Split[1] + "," + replyFromBob.substring(len/2, len);
		System.out.println("The attack message is " + attackMessage);

		//for second connection to perfom attack
		socket_Bob_2 = new Socket("localhost", 5555);
		out_Bob_2 = new PrintWriter(socket_Bob_2.getOutputStream(), true);
		in_Bob_2 = new BufferedReader(new InputStreamReader(
				socket_Bob_2.getInputStream()));

		String newReplyFromBob = sendAndGet(attackMessage, in_Bob_2, out_Bob_2);
		if(newReplyFromBob.contains("error")) {
			System.out.println("Oh my Gosh!, Bob has detected some impersonation error, I am exiting");
			System.out.println("This is what Bob replied when I tried to impersonate Alice, " + newReplyFromBob);
			System.out.println("************End of protocol ***********");
			System.exit(0);
		}
		System.out.println("Message from Bob, which I am going to use in first connection, " + newReplyFromBob);

		//closing the second connection, since required information is obtained. 
		out_Bob_2.close();
		in_Bob_2.close();
		socket_Bob_2.close();

		//The last message obtained will be sent in the first connection
		String replyToFinishAttack = newReplyFromBob.substring(0,len/2);
		System.out.println(sendAndGet("33" +  "," + replyToFinishAttack, in_Bob, out_Bob));
		System.out.println("Yeah!!, I made Bob believe that I am alice");

		//code to close the connections

		out_Bob.close();
		in_Bob.close();
		socket_Bob.close();

	}

	/**
	 * This is a method to send and receive the packets. Generic method
	 * @param message1 is the message to be sent
	 * @param in is the Inputstream for the socket to be used
	 * @param out is the output stream used
	 */
	private static String sendAndGet(String message1, BufferedReader in, PrintWriter out) throws IOException {

		out.println(message1);
		String message2 = "";
		String s;
		int flag = 0;
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

}

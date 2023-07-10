package com.hust.cysec.vtapi.main;
import com.hust.cysec.vtapi.object_scan.*;
// mvn clean compile assembly:single

import java.awt.*;
import java.io.IOException;
import java.util.*;

import javax.swing.*;

import org.knowm.xchart.BitmapEncoder;
import org.knowm.xchart.PieChart;
import org.knowm.xchart.SwingWrapper;
import org.knowm.xchart.BitmapEncoder.BitmapFormat;

import java.io.File;

public class App 
{
    public static final String API_KEY = "740bce69a223d9434f8c789ce8b432e3e15cbfb4e8bf78b72a6fa41396b8b53a";
	public static final String INVALID_INPUT_ER = "ERROR: Invalid Input.\n";
	public static final String GET_REPORT_NOTI = "...Getting report...";
    
    public static void main( String[] args ) throws IOException, InterruptedException
    {
    	Scanner input = new Scanner(System.in);
		boolean running = true;
    	int choice;
        do {
        	System.out.println("\n***** JAVA VIRUSTOTAL API *****");
            System.out.println("1. File\n2. URL\n3. Domain\n4. IP Address\n0. Exit");
            System.out.println("*******************************");
            System.out.print("> Please choose object to analyze: ");
            
            if(input.hasNextInt()) {
            	   choice = input.nextInt();
            	   input.nextLine();
            }
            else {
            	input.nextLine();
            	System.out.println(INVALID_INPUT_ER);
            	Thread.sleep(1000);
            	continue;
            }
              
            switch (choice) {
            	case 1:
	            	System.out.println("STARTING: File Analysis");
	            	System.out.println("\n*** CHOOSE FILE ***");
	            	System.out.println("a) Press ENTER to Browse Files...");
	            	System.out.println("b) OR INPUT Filename (same directory) to upload...");
	            	System.out.println("c) OR INPUT File's MD5/SHA1/SHA256 to search.");
	            	System.out.println("*******************");
	            	System.out.print("> Input: ");
	            	String filename = input.nextLine().strip();
	            	FileScan fileS = new FileScan();
	            	if (filename.isBlank()) {
	            		// Mode: Choose File to Upload
	                	UploadFile file = new UploadFile();
	                	fileS.setFilepath(file.getFile());
	            	} else {
	            		// Mode: Find File in directory to Upload
	            		File file = new File(filename);
	            		fileS.setFilepath(file);
	            	}
	                
	            	if (fileS.isValid()) {
	            		System.out.println("...Uploading & Scanning...");
	            		fileS.post(API_KEY);
	            	} else if (filename.matches("[a-fA-F0-9]{64}") || filename.matches("[a-fA-F0-9]{40}") || filename.matches("[a-fA-F0-9]{32}")) {
	            		// Mode: Try MD5/SHA1/SHA256 File Lookup
	            		System.out.println("...Assuming File MD5/SHA1/SHA256 Lookup...");
	            		fileS.setObjectId(filename);
	            		fileS.setFilepath(null);
	            		Thread.sleep(250);
	            	}
	            	
	            	System.out.println(GET_REPORT_NOTI);
            		fileS.getReport(API_KEY);
            		if (fileS.getJson() == null) {
            			System.out.println("ERROR: No file to analyze!\n");
	            		Thread.sleep(1000);
	            		break;
            		}
            		actionsMenu(fileS, input);
            		Thread.sleep(1000);
	                break;

            	case 2:
            		System.out.println("STARTING: URL Analysis");
                	System.out.print("> Input URL (or Enter to cancel): ");
                	String url = input.nextLine().strip();
                	System.out.println("");
                	URLScan urlS = new URLScan();
                	if (!url.isBlank()) {
    	            	urlS.setName(url);
    	            	System.out.println("...Scanning...");
    	            	urlS.post(API_KEY);
                	} else{
                    	System.out.println(INVALID_INPUT_ER);
                    	Thread.sleep(1000);
                    	break;
                    }
                	
                	if (urlS.getObjectId() != null) {
                		System.out.println(GET_REPORT_NOTI);
    	            	urlS.getReport(API_KEY);
    	            	actionsMenu(urlS, input);
                	}
                	Thread.sleep(1000);
                	break;
            	case 3:
            		System.out.println("STARTING: Domain Analysis");
	            	System.out.print("> Input Domain (or Enter to cancel): ");
	            	String domain = input.nextLine().strip();
	            	DomainScan domainS = new DomainScan();
	            	domainS.setName(domain);
	            	
	            	if (domainS.isValid()) {
	            		System.out.println(GET_REPORT_NOTI);
		            	domainS.getReport(API_KEY);
	            	} else{
	            		System.out.println(INVALID_INPUT_ER);
                    	Thread.sleep(1000);
                    	break;
	                }

	            	actionsMenu(domainS, input);
                	Thread.sleep(1000);
                	break;
            	case 4:
            		System.out.println("STARTING: IP Analysis");
	            	System.out.print("> Input IP (or Enter to cancel): ");
	            	String ip = input.nextLine().strip();
	            	IPScan ipS = new IPScan();
	            	ipS.setName(ip);
	            	
	            	if (ipS.isValid() ) {
	            		System.out.println(GET_REPORT_NOTI);
		            	ipS.getReport(API_KEY);
	            	} else{
	            		System.out.println("ERROR: Invalid Input...\n");
                    	Thread.sleep(1000);
                    	break;
	                }
	            	
	            	actionsMenu(ipS, input);
                	Thread.sleep(1000);
                	break;
            	case 0:
            		System.out.println("Good bye!");
					running = false;
					break;
            	default:
            		System.out.println(INVALID_INPUT_ER);
                	Thread.sleep(1000);
                	break;
            }
        } while (running);
		System.exit(0);
    }
    
    public static void actionsMenu (Scan ss, Scanner keyboard) throws InterruptedException, IOException {
    	int choice = -1;
    	String extra = "";
		if (ss instanceof FileScan || ss instanceof URLScan)
			extra = "\n5. Update or Re-do Analysis results (File/URL)";
    	do {
    		Thread.sleep(1000);
    		System.out.println("\n*** OPTIONS ***");
            System.out.println("1. View Analysis Summary\n2. View Pie Chart\n3. Save to JSON\n4. Save to Excel" + extra +"\n0. Exit to Main menu");
            System.out.println("***************");
            System.out.print("> Please choose: ");
    		
    		if(keyboard.hasNextInt()) {
    			choice = keyboard.nextInt();
         	   	keyboard.nextLine();
    		}
            else {
            	keyboard.nextLine();
             	System.out.println(INVALID_INPUT_ER);
             	continue;
            }
    		
    		switch (choice) {
    		case 1:
    			ss.printSummary();
    			break;
    		case 2:
    			PieChart chart = ss.toChart();
    			if (chart == null)
    				break;
    			do {
    	    		Thread.sleep(1000);
    	    		System.out.println("\n***CHART OPTIONS ***");
    	            System.out.println("1. Show Chart\n2. Save Chart to PNG\n0. Back to Options menu");
    	            System.out.println("***************");
    	            System.out.print("> Please choose: ");
	    			int chartOption = 0;
	    			if(keyboard.hasNextInt()) {
	    				chartOption = keyboard.nextInt();
	             	   	keyboard.nextLine();
	        		} else {
	        			keyboard.nextLine();
	                 	System.out.println(INVALID_INPUT_ER);
	                 	continue;
	                }
	    			if (chartOption == 1) {
	    				// Show Chart
	    				JFrame frame = new SwingWrapper<>(chart).displayChart();
	    				frame.setExtendedState(java.awt.Frame.ICONIFIED);
	    				frame.setExtendedState(Frame.NORMAL);
	    				frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
	    				continue;
	    			} else if (chartOption == 2) {
	    				// Save Chart in high-res png
	    			    BitmapEncoder.saveBitmapWithDPI(chart,new File(System.getProperty("user.dir")).getParent() + "/Project1/vtapi/data/PieChart/" + ss.genSaveName("chart"), BitmapFormat.PNG, 300);
	    			    System.out.println("...Saved Chart!\n");
	    			    continue;
	    			} else if (chartOption == 0) {
	    			    break;
	    			} else {
	    				System.out.println(INVALID_INPUT_ER);
	                 	continue;
	    			}
    			} while (true);
    			break;
    		case 3:
    			System.out.println("...Saving...");
    			if (ss.toJsonReport())
    				System.out.println("...Saved to JSON!");
    			else
    				System.out.println("...Save Failed.");
    			break;
    		case 4:
    			System.out.println("...Saving...");
    			if(ss.toExcelReport())
    				System.out.println("...Saved to Excel!");
    			else
    				System.out.println("...Save Failed.");
    			break;
    		case 0:
    			System.out.println("\n");
    			return;
    		case 5:
    			if (ss instanceof FileScan || ss instanceof URLScan) {
    				if (ss.getTime() == 0) {
    					System.out.println("...Retry getting report...");
    					ss.getReport(API_KEY);
    					if (ss.getTime() != 0)
    						System.out.println("...Updated finished analysis!");
    				}
    				else {
    					long oldtime = ss.getTime();
    					System.out.println("...Updating results/Requesting re-analyze...");
    					ss.getReport(API_KEY);
    					if (ss.getTime() == oldtime)
    						System.out.println("...No new analysis found.\n(Updated VT results may need a few minutes)");
    					else
    						System.out.println("...Updated new analysis!");
    				}
        			break;
    			}
			break;
    		default:
    			System.out.println(INVALID_INPUT_ER);
             	continue;
    		}
    	} while (true);
    }
}
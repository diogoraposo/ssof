package braindeadanalyzer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.TreeMap;

public class Analyzer {

	public static void main(String[] args) {
		
		boolean DEBUG = true;
		
		File patternsfile = new File(System.getProperty("user.dir") + "/src/braindeadanalyzer/patterns");
		TreeMap<String, Vulnerability> vulns = new TreeMap<String, Vulnerability>();
		
		
		//Read patterns file
		try (BufferedReader br = new BufferedReader(new FileReader(patternsfile))) {
		    String line;
		    while ((line = br.readLine()) != null) {
		    	Vulnerability vuln = new Vulnerability(line);
		    	line = br.readLine();
		    	String[] eps = line.split(",");
		    	for(String s: eps){
		    		vuln.addEntryPoint(s);
		    	}
		    	line = br.readLine();
		    	String[] funcs = line.split(",");
		    	for(String s: funcs){
		    		vuln.addSanitFunction(s);
		    	}
		    	line = br.readLine();
		    	String[] sanits = line.split(",");
		    	for(String s: sanits){
		    		vuln.addSensitiveSink(s);
		    	}
		    	line=br.readLine();
		    	vulns.put(vuln.get_description(), vuln);
		    	if(DEBUG) System.out.println(vuln.toString());
		    }
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}

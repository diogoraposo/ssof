package braindeadanalyzer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.TreeMap;

public class Analyzer {

	public static void main(String[] args) {
		
		File patternsfile = new File(System.getProperty("user.dir") + "/src/braindeadanalyzer/patterns");
		TreeMap<String, Vulnerability> entryPoints = new TreeMap<String, Vulnerability>();
		TreeMap<String, Vulnerability> sanitizationFunctions = new TreeMap<String, Vulnerability>();
		TreeMap<String, Vulnerability> sensitiveSinks = new TreeMap<String, Vulnerability>();
		
		try (BufferedReader br = new BufferedReader(new FileReader(patternsfile))) {
		    String line;
		    while ((line = br.readLine()) != null) {
		       System.out.println(line);
		    }
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
